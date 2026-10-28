package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) actionError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrNotFound), errors.Is(err, actions.ErrActionNotFound):
		WriteError(w, 404, "inexistent_resource", "The requested Action resource does not exist")
	case errors.Is(err, build.ErrResolveTimeout), errors.Is(err, store.ErrActionsUnavailable):
		WriteError(w, 503, "actions_unavailable", "The Actions build service is unavailable")
	case errors.Is(err, store.ErrBuildNotReady), errors.Is(err, actions.ErrDraftNotBuilt), errors.Is(err, actions.ErrInvalidPayload), errors.Is(err, store.ErrInvalid), errors.Is(err, build.ErrInvalid):
		Fail(w, badBody("invalid Action or draft dependencies are not built"))
	case errors.Is(err, store.ErrConflict):
		Fail(w, badBody("The Action name is already in use"))
	default:
		Fail(w, internalError(h, r, "Actions operation", err))
	}
}

// Action control fields have no nullable values. Event payloads use their
// own decoder because arbitrary event JSON may contain null.
func actionControlValue(raw json.RawMessage) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return badBody("invalid JSON")
	}
	var check func(any) bool
	check = func(v any) bool {
		switch x := v.(type) {
		case nil:
			return false
		case []any:
			for _, v := range x {
				if !check(v) {
					return false
				}
			}
		case map[string]any:
			for _, v := range x {
				if !check(v) {
					return false
				}
			}
		}
		return true
	}
	if !check(value) {
		return badBody("Action control properties must not be null")
	}
	return nil
}
func actionNoBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil || len(bytes.TrimSpace(data)) > 0 {
		return badBody("this operation does not accept a body")
	}
	return nil
}
func actionQuery(r *http.Request, allowed ...string) error {
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		if err := actionNoBody(r); err != nil {
			return err
		}
	}
	q, err := urlQuery(r)
	if err != nil {
		return err
	}
	for k, vs := range q {
		if !slices.Contains(allowed, k) || len(vs) != 1 || vs[0] == "" {
			return badQuery("unsupported or invalid query parameter %q", k)
		}
	}
	return nil
}

// urlQuery also rejects malformed escaping, which URL.Query otherwise discards.
func urlQuery(r *http.Request) (map[string][]string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badQuery("invalid query string")
	}
	return q, nil
}
func actionPaging(r *http.Request, extra ...string) (store.PageRequest, error) {
	if err := actionQuery(r, append([]string{"page", "per_page"}, extra...)...); err != nil {
		return store.PageRequest{}, err
	}
	page, per, _, err := Page(r)
	return store.PageRequest{Page: page, PerPage: per}, err
}
func validActionTrigger(trigger string) bool {
	return slices.ContainsFunc(actionsrules.Inventory().Triggers, func(t actionsrules.TriggerContract) bool { return t.ID == trigger })
}
func actionTriggerView(trigger string) map[string]any {
	version := "v3"
	for _, t := range actionsrules.Inventory().Triggers {
		if t.ID == trigger {
			if t.Version != "" {
				version = t.Version
			} else if trigger == actions.TriggerCredentialsExchange {
				version = "v2"
			}
			break
		}
	}
	return map[string]any{"id": trigger, "version": version, "binding_policy": "trigger-bound"}
}
func dependencyViews(ds []store.Dependency) []map[string]any {
	out := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		out = append(out, map[string]any{"name": d.Name, "version": d.Version})
	}
	return out
}
func secretViews(ss []store.ActionSecret) []map[string]any {
	out := make([]map[string]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, map[string]any{"name": s.Name, "updated_at": s.UpdatedAt})
	}
	return out
}
func (h *Handlers) recoverAction(ctx context.Context, a *store.Action) error {
	if a.DraftBuildID == "" {
		return nil
	}
	b, err := h.Store.Actions().GetBuild(ctx, a.TenantID, a.DraftBuildID)
	if err != nil {
		return err
	}
	if b.Status == store.BuildPending || b.Status == store.BuildBuilding {
		if h.Actions == nil || h.Actions.Builds == nil {
			return &Error{Status: 503, Code: "actions_unavailable", Message: "The Actions build service is unavailable"}
		}
		return h.Actions.Builds.Recover(ctx, a.TenantID, b.ID)
	}
	return nil
}
func (h *Handlers) actionView(ctx context.Context, a *store.Action) (map[string]any, error) {
	if err := h.recoverAction(ctx, a); err != nil {
		return nil, err
	}
	out := map[string]any{"id": a.ID, "name": a.Name, "supported_triggers": []map[string]any{actionTriggerView(a.Trigger)}, "code": a.Code, "modules": moduleRefViews(a.Modules), "runtime": a.Runtime, "dependencies": dependencyViews(a.Dependencies), "secrets": secretViews(a.Secrets), "created_at": a.CreatedAt, "updated_at": a.UpdatedAt, "status": "pending", "errors": []string{}, "all_changes_deployed": false}
	var b *store.Build
	if a.DraftBuildID != "" {
		var err error
		b, err = h.Store.Actions().GetBuild(ctx, a.TenantID, a.DraftBuildID)
		if err != nil {
			return nil, err
		}
		out["status"] = b.Status
		if b.Errors != nil {
			out["errors"] = b.Errors
		}
		if !b.BuiltAt.IsZero() {
			out["built_at"] = b.BuiltAt
		}
	}
	if a.DeployedVersionID != "" {
		v, err := h.Store.Actions().GetVersion(ctx, a.TenantID, a.ID, a.DeployedVersionID)
		if err != nil {
			return nil, err
		}
		vv, err := h.actionVersionView(ctx, v)
		if err != nil {
			return nil, err
		}
		out["deployed_version"] = vv
		out["all_changes_deployed"] = b != nil && a.Code == v.Code && a.Runtime == v.Runtime && a.DraftBuildID == v.BuildID && slices.Equal(a.Modules, v.Modules) && slices.Equal(b.Resolved, v.Dependencies) && slices.EqualFunc(a.Secrets, v.Secrets, func(a, b store.ActionSecret) bool { return a.Name == b.Name && bytes.Equal(a.Sealed, b.Sealed) })
	}
	return out, nil
}
func (h *Handlers) writeAction(w http.ResponseWriter, r *http.Request, a *store.Action, status int) {
	v, err := h.actionView(r.Context(), a)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	writeJSON(w, status, v)
}

// readAction applies only explicitly supplied draft fields. Secret values may
// be omitted for existing names; responses can safely be round tripped.
func (h *Handlers) readAction(r *http.Request, a *store.Action, create bool) (bool, error) {
	body, err := decodeObject(r)
	if err != nil {
		return false, err
	}
	if create && (body["name"] == nil || body["supported_triggers"] == nil) {
		return false, badBody("name and supported_triggers are required")
	}
	deploy := false
	for k, raw := range body {
		if err := actionControlValue(raw); err != nil {
			return false, err
		}
		switch k {
		case "name":
			err = decodeString(raw, &a.Name)
		case "code":
			err = decodeString(raw, &a.Code)
		case "runtime":
			err = decodeString(raw, &a.Runtime)
			if err == nil && a.Runtime != actionsrules.Runtime {
				return false, badBody("runtime must be node22")
			}
		case "supported_triggers":
			var ts []struct {
				ID      *string `json:"id"`
				Version *string `json:"version,omitempty"`
			}
			err = decodeStrict(raw, &ts)
			if err == nil {
				if len(ts) != 1 || ts[0].ID == nil || !validActionTrigger(*ts[0].ID) {
					return false, badBody("supported_triggers must contain one supported trigger")
				}
				if !create && a.Trigger != *ts[0].ID {
					return false, badBody("an Action's trigger cannot change")
				}
				a.Trigger = *ts[0].ID
			}
		case "modules":
			var refs []moduleRefInput
			err = decodeStrict(raw, &refs)
			if err == nil {
				a.Modules = make([]store.ModuleRef, 0, len(refs))
				for _, ref := range refs {
					a.Modules = append(a.Modules, store.ModuleRef{ModuleID: ref.ModuleID, ModuleName: ref.ModuleName, VersionID: ref.VersionID, VersionNumber: ref.VersionNumber})
				}
			}
		case "dependencies":
			var ds []struct {
				Name    *string `json:"name"`
				Version *string `json:"version,omitempty"`
			}
			err = decodeStrict(raw, &ds)
			if err == nil {
				a.Dependencies = make([]store.Dependency, 0, len(ds))
				for _, d := range ds {
					if d.Name == nil {
						return false, badBody("dependency name is required")
					}
					v := ""
					if d.Version != nil {
						v = *d.Version
					}
					a.Dependencies = append(a.Dependencies, store.Dependency{Name: *d.Name, Version: v})
				}
			}
		case "secrets":
			var ss []struct {
				Name  *string `json:"name"`
				Value *string `json:"value,omitempty"`
			}
			err = decodeStrict(raw, &ss)
			if err == nil {
				old := a.Secrets
				a.Secrets = make([]store.ActionSecret, 0, len(ss))
				for _, s := range ss {
					if s.Name == nil {
						return false, badBody("secret name is required")
					}
					if s.Value == nil {
						idx := slices.IndexFunc(old, func(o store.ActionSecret) bool { return o.Name == *s.Name })
						if idx < 0 {
							return false, badBody("new secret requires a value")
						}
						a.Secrets = append(a.Secrets, old[idx])
						continue
					}
					if len(*s.Value) > actionsrules.Inventory().Limits["secret_value_max"] {
						return false, badBody("secret value exceeds 4096 bytes")
					}
					sealed, e := keys.SealActionSecret(h.Wrapper, a.TenantID, a.ID, *s.Name, *s.Value)
					if e != nil {
						return false, e
					}
					a.Secrets = append(a.Secrets, store.ActionSecret{Name: *s.Name, Sealed: sealed, UpdatedAt: h.now()})
				}
			}
		case "deploy":
			if !create {
				return false, badBody("unknown property %q", k)
			}
			err = decodeStrict(raw, &deploy)
		default:
			return false, badBody("unknown property %q", k)
		}
		if err != nil {
			return false, badBody("%s: %v", k, err)
		}
	}
	if errs := actionsrules.NormalizeAction(a); len(errs) > 0 {
		return false, badBody("%v", errors.Join(errs...))
	}
	return deploy, nil
}
func (h *Handlers) queueAction(r *http.Request, a *store.Action) error {
	if h.Actions == nil || h.Actions.Builds == nil {
		return &Error{Status: 503, Code: "actions_unavailable", Message: "The Actions build service is unavailable"}
	}
	id, err := h.Actions.Builds.Queue(r.Context(), a.TenantID, a.Dependencies, a.Runtime)
	if err == nil {
		a.DraftBuildID = id
	}
	return err
}
func (h *Handlers) CreateAction(w http.ResponseWriter, r *http.Request) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	a := &store.Action{TenantID: resolved(r).ID, ID: "act_" + secrets.RandomString(18), CreatedAt: h.now(), UpdatedAt: h.now()}
	deploy, err := h.readAction(r, a, true)
	if err == nil {
		err = h.queueAction(r, a)
	}
	if err == nil && deploy {
		err = h.waitActionBuild(r.Context(), a)
	}
	if err == nil {
		err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
			if err := tx.Actions().CreateAction(r.Context(), a); err != nil {
				return err
			}
			if deploy {
				v, err := tx.Actions().Deploy(r.Context(), a.TenantID, a.ID, "")
				if err != nil {
					return err
				}
				a.DeployedVersionID = v.ID
				h.Actions.Builds.PrewarmBuild(a.TenantID, v.BuildID)
			}
			return nil
		})
	}
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	a, err = h.Store.Actions().GetAction(r.Context(), a.TenantID, a.ID)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	h.audit(r, "create Action", "id", a.ID)
	h.writeAction(w, r, a, 201)
}
func (h *Handlers) waitActionBuild(ctx context.Context, a *store.Action) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		b, err := h.Store.Actions().GetBuild(ctx, a.TenantID, a.DraftBuildID)
		if err != nil {
			return err
		}
		switch b.Status {
		case store.BuildBuilt:
			return nil
		case store.BuildFailed:
			return badBody("Action dependency build failed")
		}
		select {
		case <-ctx.Done():
			return &Error{Status: 503, Code: "actions_unavailable", Message: "The Action build did not finish in time"}
		case <-tick.C:
		}
	}
}
func (h *Handlers) GetAction(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	a, err := h.Store.Actions().GetAction(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	h.writeAction(w, r, a, 200)
}
func (h *Handlers) UpdateAction(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	a, err := h.Store.Actions().GetAction(r.Context(), resolved(r).ID, id)
	if err == nil {
		_, err = h.readAction(r, a, false)
	}
	if err == nil {
		err = h.queueAction(r, a)
	}
	if err == nil {
		a.UpdatedAt = h.now()
		err = h.Store.Actions().UpdateAction(r.Context(), a)
	}
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	a, err = h.Store.Actions().GetAction(r.Context(), a.TenantID, a.ID)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	h.audit(r, "update Action", "id", id)
	h.writeAction(w, r, a, 200)
}
func (h *Handlers) DeleteAction(w http.ResponseWriter, r *http.Request, id string) {
	err := actionQuery(r, "force")
	force := false
	if err == nil {
		force, err = boolParam(r, "force", false)
	}
	if err == nil {
		err = h.Store.Actions().DeleteAction(r.Context(), resolved(r).ID, id, force)
	}
	if errors.Is(err, store.ErrConflict) {
		err = badBody("bound Actions require force=true")
	}
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	h.audit(r, "delete Action", "id", id)
	w.WriteHeader(204)
}
func (h *Handlers) GetActions(w http.ResponseWriter, r *http.Request) {
	p, err := actionPaging(r, "triggerId", "actionName", "deployed", "installed")
	if err != nil {
		Fail(w, err)
		return
	}
	q := r.URL.Query()
	if q.Has("triggerId") && !validActionTrigger(q.Get("triggerId")) {
		Fail(w, badQuery("unsupported triggerId"))
		return
	}
	for _, k := range []string{"deployed", "installed"} {
		if _, err := boolParam(r, k, false); err != nil {
			Fail(w, err)
			return
		}
	}
	// The store filters trigger and pages; remaining public filters are applied
	// before pagination, including totals, across every store page.
	items := []store.Action{}
	for page := 0; ; page++ {
		res, e := h.Store.Actions().ListActions(r.Context(), resolved(r).ID, store.ActionFilter{Trigger: q.Get("triggerId"), PageRequest: store.PageRequest{Page: page, PerPage: store.MaxPerPage}})
		if e != nil {
			h.actionError(w, r, e)
			return
		}
		for _, a := range res.Items {
			if q.Has("actionName") && a.Name != q.Get("actionName") {
				continue
			}
			if q.Has("deployed") && (a.DeployedVersionID != "") != (q.Get("deployed") == "true") {
				continue
			}
			if q.Get("installed") == "true" {
				continue
			}
			items = append(items, a)
		}
		if len(res.Items) == 0 || (page+1)*store.MaxPerPage >= res.Total {
			break
		}
	}
	out := []map[string]any{}
	start := min(p.Page*p.PerPage, len(items))
	for _, a := range items[start:min(start+p.PerPage, len(items))] {
		v, e := h.actionView(r.Context(), &a)
		if e != nil {
			h.actionError(w, r, e)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, 200, map[string]any{"actions": out, "total": len(items), "page": p.Page, "per_page": p.PerPage})
}

type moduleRefInput struct {
	ModuleID      string `json:"module_id,omitempty"`
	ModuleName    string `json:"module_name,omitempty"`
	VersionID     string `json:"module_version_id,omitempty"`
	VersionNumber int    `json:"module_version_number,omitempty"`
}

func moduleRefViews(refs []store.ModuleRef) []map[string]any {
	out := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]any{"module_id": r.ModuleID, "module_name": r.ModuleName, "module_version_id": r.VersionID, "module_version_number": r.VersionNumber})
	}
	return out
}
