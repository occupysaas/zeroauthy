package mgmt

import (
	"context"
	"io"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) actionVersionView(ctx context.Context, v *store.ActionVersion) (map[string]any, error) {
	out := map[string]any{"id": v.ID, "action_id": v.ActionID, "number": v.Number, "code": v.Code, "modules": moduleRefViews(v.Modules), "runtime": v.Runtime, "dependencies": dependencyViews(v.Dependencies), "secrets": secretViews(v.Secrets), "created_at": v.CreatedAt, "status": "built"}
	b, err := h.Store.Actions().GetBuild(ctx, v.TenantID, v.BuildID)
	if err != nil {
		return nil, err
	}
	if !b.BuiltAt.IsZero() {
		out["built_at"] = b.BuiltAt
	}
	return out, nil
}
func (h *Handlers) writeActionVersion(w http.ResponseWriter, r *http.Request, v *store.ActionVersion, status int) {
	out, err := h.actionVersionView(r.Context(), v)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	writeJSON(w, status, out)
}
func (h *Handlers) DeployAction(w http.ResponseWriter, r *http.Request, id string) {
	err := actionQuery(r)
	if err == nil {
		err = actionNoBody(r)
	}
	var a *store.Action
	if err == nil {
		a, err = h.Store.Actions().GetAction(r.Context(), resolved(r).ID, id)
	}
	if err == nil {
		err = h.recoverAction(r.Context(), a)
	}
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	v, err := h.Store.Actions().Deploy(r.Context(), a.TenantID, id, "")
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	if h.Actions != nil && h.Actions.Builds != nil {
		h.Actions.Builds.PrewarmBuild(a.TenantID, v.BuildID)
	}
	h.audit(r, "deploy Action", "id", id, "version", v.ID)
	h.writeActionVersion(w, r, v, 202)
}
func (h *Handlers) GetActionVersions(w http.ResponseWriter, r *http.Request, id string) {
	p, err := actionPaging(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err = h.Store.Actions().GetAction(r.Context(), resolved(r).ID, id); err != nil {
		h.actionError(w, r, err)
		return
	}
	result, err := h.Store.Actions().ListVersions(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	out := []map[string]any{}
	for _, v := range result.Items {
		vv, err := h.actionVersionView(r.Context(), &v)
		if err != nil {
			h.actionError(w, r, err)
			return
		}
		out = append(out, vv)
	}
	writeJSON(w, 200, map[string]any{"versions": out, "total": result.Total, "page": p.Page, "per_page": p.PerPage})
}
func (h *Handlers) GetActionVersion(w http.ResponseWriter, r *http.Request, id, versionID string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	v, err := h.Store.Actions().GetVersion(r.Context(), resolved(r).ID, id, versionID)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	h.writeActionVersion(w, r, v, 200)
}
func (h *Handlers) DeployActionVersion(w http.ResponseWriter, r *http.Request, id, versionID string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	// The rollback body is optional, but any supplied body must be strict.
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		Fail(w, badBody("unreadable body"))
		return
	}
	var body struct {
		UpdateDraft bool `json:"update_draft"`
	}
	if len(data) > 0 {
		if err := actionControlValue(data); err != nil {
			Fail(w, err)
			return
		}
		if err := decodeStrict(data, &body); err != nil {
			Fail(w, badBody("%v", err))
			return
		}
	}
	var out *store.ActionVersion
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		v, err := tx.Actions().Deploy(r.Context(), resolved(r).ID, id, versionID)
		if err != nil {
			return err
		}
		if body.UpdateDraft {
			a, err := tx.Actions().GetAction(r.Context(), resolved(r).ID, id)
			if err != nil {
				return err
			}
			a.Modules = v.Modules
			a.Code, a.Runtime, a.Dependencies, a.Secrets, a.DraftBuildID = v.Code, v.Runtime, v.Dependencies, v.Secrets, v.BuildID
			a.UpdatedAt = h.now()
			if err := tx.Actions().UpdateAction(r.Context(), a); err != nil {
				return err
			}
		}
		out = v
		return nil
	})
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	if h.Actions != nil && h.Actions.Builds != nil {
		h.Actions.Builds.PrewarmBuild(out.TenantID, out.BuildID)
	}
	h.audit(r, "rollback Action", "id", id, "version", out.ID)
	h.writeActionVersion(w, r, out, 202)
}
