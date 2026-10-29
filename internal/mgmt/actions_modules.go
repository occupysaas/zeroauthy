package mgmt

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) moduleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrConflict):
		WriteError(w, 409, "conflict", "Module name already exists or no changes to publish")
	case errors.Is(err, store.ErrPrecondition):
		WriteError(w, 412, "precondition_failed", "Module is in use or version limit reached")
	default:
		h.actionError(w, r, err)
	}
}
func moduleVersionView(v *store.ActionModuleVersion) map[string]any {
	return map[string]any{"id": v.ID, "module_id": v.ModuleID, "version_number": v.Number, "code": v.Code, "dependencies": dependencyViews(v.Dependencies), "secrets": secretViews(v.Secrets), "created_at": v.CreatedAt}
}
func (h *Handlers) moduleView(ctx context.Context, m *store.ActionModule) (map[string]any, error) {
	out := map[string]any{"id": m.ID, "name": m.Name, "code": m.Code, "dependencies": dependencyViews(m.Dependencies), "secrets": secretViews(m.Secrets), "all_changes_published": m.AllChangesPublished, "created_at": m.CreatedAt, "updated_at": m.UpdatedAt, "status": "pending", "errors": []string{}}
	if m.DraftBuildID != "" {
		b, err := h.Store.Actions().GetBuild(ctx, m.TenantID, m.DraftBuildID)
		if err != nil {
			return nil, err
		}
		if (b.Status == store.BuildPending || b.Status == store.BuildBuilding) && h.Actions != nil && h.Actions.Builds != nil {
			if err := h.Actions.Builds.Recover(ctx, m.TenantID, b.ID); err != nil {
				return nil, err
			}
		}
		out["status"] = b.Status
		if b.Errors != nil {
			out["errors"] = b.Errors
		}
		if !b.BuiltAt.IsZero() {
			out["built_at"] = b.BuiltAt
		}
	}
	users, err := h.Store.Actions().ModuleUsers(ctx, m.TenantID, m.ID, store.PageRequest{PerPage: 1})
	if err != nil {
		return nil, err
	}
	out["actions_using_module_total"] = users.Total
	if m.LatestVersionNumber > 0 {
		out["latest_version_number"] = m.LatestVersionNumber
		vs, err := h.Store.Actions().ListModuleVersions(ctx, m.TenantID, m.ID, store.PageRequest{PerPage: 1})
		if err != nil {
			return nil, err
		}
		if len(vs.Items) > 0 {
			out["latest_version"] = moduleVersionView(&vs.Items[0])
		}
	}
	return out, nil
}
func (h *Handlers) writeModule(w http.ResponseWriter, r *http.Request, m *store.ActionModule, status int) {
	out, err := h.moduleView(r.Context(), m)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	writeJSON(w, status, out)
}
func (h *Handlers) readModule(r *http.Request, m *store.ActionModule, create bool) (bool, error) {
	body, err := decodeObject(r)
	if err != nil {
		return false, err
	}
	if create && (body["name"] == nil || body["code"] == nil) {
		return false, badBody("name and code are required")
	}
	publish := false
	for k, raw := range body {
		if err := actionControlValue(raw); err != nil {
			return false, err
		}
		switch k {
		case "name":
			if !create {
				return false, badBody("name cannot change")
			}
			err = decodeString(raw, &m.Name)
		case "code":
			err = decodeString(raw, &m.Code)
		case "api_version":
			if !create {
				return false, badBody("unknown property %q", k)
			}
			var v string
			err = decodeString(raw, &v)
			if err == nil && (!utf8.ValidString(v) || utf8.RuneCountInString(v) > 20 || strings.ContainsRune(v, 0)) {
				return false, badBody("api_version must be at most 20 characters without NUL")
			}
		case "publish":
			if !create {
				return false, badBody("unknown property %q", k)
			}
			err = decodeStrict(raw, &publish)
		case "dependencies":
			var ds []struct {
				Name    *string `json:"name"`
				Version string  `json:"version,omitempty"`
			}
			err = decodeStrict(raw, &ds)
			if err == nil {
				m.Dependencies = make([]store.Dependency, 0, len(ds))
				for _, d := range ds {
					if d.Name == nil {
						return false, badBody("dependency name required")
					}
					m.Dependencies = append(m.Dependencies, store.Dependency{Name: *d.Name, Version: d.Version})
				}
			}
		case "secrets":
			var ss []struct {
				Name  *string `json:"name"`
				Value *string `json:"value,omitempty"`
			}
			err = decodeStrict(raw, &ss)
			if err == nil {
				old := m.Secrets
				m.Secrets = make([]store.ActionSecret, 0, len(ss))
				for _, s := range ss {
					if s.Name == nil {
						return false, badBody("secret name required")
					}
					if s.Value == nil {
						idx := slices.IndexFunc(old, func(v store.ActionSecret) bool { return v.Name == *s.Name })
						if idx < 0 {
							return false, badBody("new secret requires a value")
						}
						m.Secrets = append(m.Secrets, old[idx])
						continue
					}
					if len(*s.Value) > actionsrules.Inventory().Limits["secret_value_max"] {
						return false, badBody("secret value too long")
					}
					sealed, e := keys.SealModuleSecret(h.Wrapper, m.TenantID, m.ID, *s.Name, *s.Value)
					if e != nil {
						return false, e
					}
					m.Secrets = append(m.Secrets, store.ActionSecret{Name: *s.Name, Sealed: sealed, UpdatedAt: h.now()})
				}
			}
		default:
			return false, badBody("unknown property %q", k)
		}
		if err != nil {
			return false, badBody("%s: %v", k, err)
		}
	}
	if strings.ContainsRune(m.Code, 0) {
		return false, badBody("module code must not contain NUL")
	}
	if errs := actionsrules.NormalizeModule(m); len(errs) > 0 {
		return false, badBody("%v", errors.Join(errs...))
	}
	return publish, nil
}
func (h *Handlers) queueModule(r *http.Request, m *store.ActionModule) error {
	a := &store.Action{TenantID: m.TenantID, Runtime: actionsrules.Runtime, Dependencies: m.Dependencies}
	err := h.queueAction(r, a)
	m.DraftBuildID = a.DraftBuildID
	return err
}
func (h *Handlers) CreateActionModule(w http.ResponseWriter, r *http.Request) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	m := &store.ActionModule{TenantID: resolved(r).ID, ID: "am_" + secrets.RandomString(18), CreatedAt: h.now(), UpdatedAt: h.now()}
	pub, err := h.readModule(r, m, true)
	if err == nil {
		if _, getErr := h.Store.Actions().GetModuleByName(r.Context(), m.TenantID, m.Name); getErr == nil {
			err = store.ErrConflict
		} else if !errors.Is(getErr, store.ErrNotFound) {
			err = getErr
		}
	}
	if err == nil {
		err = h.queueModule(r, m)
	}
	if err == nil && pub {
		err = h.waitActionBuild(r.Context(), &store.Action{TenantID: m.TenantID, DraftBuildID: m.DraftBuildID})
	}
	if err == nil {
		err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
			if err := tx.Actions().CreateModule(r.Context(), m); err != nil {
				return err
			}
			if pub {
				_, err := tx.Actions().PublishModule(r.Context(), m.TenantID, m.ID)
				return err
			}
			return nil
		})
	}
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	m, err = h.Store.Actions().GetModule(r.Context(), m.TenantID, m.ID)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.audit(r, "create Action Module", "id", m.ID)
	h.writeModule(w, r, m, 201)
}
func (h *Handlers) GetActionModule(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	m, err := h.Store.Actions().GetModule(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.writeModule(w, r, m, 200)
}
func (h *Handlers) UpdateActionModule(w http.ResponseWriter, r *http.Request, id string) {
	err := actionQuery(r)
	var m *store.ActionModule
	if err == nil {
		m, err = h.Store.Actions().GetModule(r.Context(), resolved(r).ID, id)
	}
	if err == nil {
		_, err = h.readModule(r, m, false)
	}
	if err == nil {
		err = h.queueModule(r, m)
	}
	if err == nil {
		m.UpdatedAt = h.now()
		err = h.Store.Actions().UpdateModule(r.Context(), m)
	}
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	m, err = h.Store.Actions().GetModule(r.Context(), m.TenantID, m.ID)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.audit(r, "update Action Module", "id", id)
	h.writeModule(w, r, m, 200)
}
func (h *Handlers) DeleteActionModule(w http.ResponseWriter, r *http.Request, id string) {
	err := actionQuery(r)
	if err == nil {
		err = h.Store.Actions().DeleteModule(r.Context(), resolved(r).ID, id)
	}
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.audit(r, "delete Action Module", "id", id)
	w.WriteHeader(204)
}
func (h *Handlers) PublishActionModule(w http.ResponseWriter, r *http.Request, id string) {
	err := actionQuery(r)
	if err == nil {
		err = actionNoBody(r)
	}
	var v *store.ActionModuleVersion
	if err == nil {
		v, err = h.Store.Actions().PublishModule(r.Context(), resolved(r).ID, id)
	}
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.audit(r, "publish Action Module", "id", id, "version", v.ID)
	writeJSON(w, 200, moduleVersionView(v))
}
func (h *Handlers) RollbackActionModule(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var vid string
	if len(body) != 1 || body["module_version_id"] == nil {
		Fail(w, badBody("module_version_id is required"))
		return
	}
	if err := decodeString(body["module_version_id"], &vid); err != nil || vid == "" {
		Fail(w, badBody("invalid module_version_id"))
		return
	}
	m, err := h.Store.Actions().RollbackModule(r.Context(), resolved(r).ID, id, vid)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	h.audit(r, "rollback Action Module", "id", id, "version", vid)
	h.writeModule(w, r, m, 200)
}
func (h *Handlers) GetActionModuleVersions(w http.ResponseWriter, r *http.Request, id string) {
	p, err := actionPaging(r)
	if err != nil {
		Fail(w, err)
		return
	}
	vs, err := h.Store.Actions().ListModuleVersions(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	out := []map[string]any{}
	for _, v := range vs.Items {
		out = append(out, moduleVersionView(&v))
	}
	writeJSON(w, 200, map[string]any{"versions": out, "total": vs.Total, "page": p.Page, "per_page": p.PerPage})
}
func (h *Handlers) GetActionModuleVersion(w http.ResponseWriter, r *http.Request, id, vid string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	if _, err := h.Store.Actions().GetModule(r.Context(), resolved(r).ID, id); err != nil {
		h.moduleError(w, r, err)
		return
	}
	v, err := h.Store.Actions().GetModuleVersion(r.Context(), resolved(r).ID, id, vid)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	writeJSON(w, 200, moduleVersionView(v))
}
func (h *Handlers) GetActionModuleActions(w http.ResponseWriter, r *http.Request, id string) {
	p, err := actionPaging(r)
	if err != nil {
		Fail(w, err)
		return
	}
	users, err := h.Store.Actions().ModuleUsers(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.moduleError(w, r, err)
		return
	}
	out := []map[string]any{}
	for _, u := range users.Items {
		refs := u.Modules
		if !u.InDraft && u.InDeployed {
			v, err := h.Store.Actions().GetVersion(r.Context(), resolved(r).ID, u.ID, u.DeployedVersionID)
			if err != nil {
				h.moduleError(w, r, err)
				return
			}
			refs = v.Modules
		}
		for _, ref := range refs {
			if ref.ModuleID == id {
				out = append(out, map[string]any{"action_id": u.ID, "action_name": u.Name, "module_version_id": ref.VersionID, "module_version_number": ref.VersionNumber, "supported_triggers": []map[string]any{actionTriggerReference(u.Trigger)}})
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"actions": out, "total": users.Total, "page": p.Page, "per_page": p.PerPage})
}
func (h *Handlers) GetActionModules(w http.ResponseWriter, r *http.Request) {
	p, err := actionPaging(r)
	if err != nil {
		Fail(w, err)
		return
	}
	all := []store.ActionModule{}
	total := 0
	// Unlike other lists, an omitted paging query returns all modules.
	for page := p.Page; ; page++ {
		req := p
		if !r.URL.Query().Has("page") && !r.URL.Query().Has("per_page") {
			req = store.PageRequest{Page: page, PerPage: store.MaxPerPage}
		}
		vs, err := h.Store.Actions().ListModules(r.Context(), resolved(r).ID, req)
		if err != nil {
			h.moduleError(w, r, err)
			return
		}
		total = vs.Total
		all = append(all, vs.Items...)
		if r.URL.Query().Has("page") || r.URL.Query().Has("per_page") || len(vs.Items) == 0 || (page+1)*req.PerPage >= total {
			break
		}
	}
	out := []map[string]any{}
	for _, m := range all {
		v, err := h.moduleView(r.Context(), &m)
		if err != nil {
			h.moduleError(w, r, err)
			return
		}
		out = append(out, v)
	}
	per := p.PerPage
	if !r.URL.Query().Has("page") && !r.URL.Query().Has("per_page") {
		per = len(all)
	}
	writeJSON(w, 200, map[string]any{"modules": out, "total": total, "page": p.Page, "per_page": per})
}
