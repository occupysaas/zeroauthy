package mgmt

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func bindingView(v store.BoundVersion) map[string]any {
	return map[string]any{"id": v.ID, "trigger_id": v.Trigger, "display_name": v.DisplayName, "action": map[string]any{"id": v.Action.ID, "name": v.Action.Name}, "created_at": v.CreatedAt, "updated_at": v.UpdatedAt}
}
func (h *Handlers) GetActionTriggers(w http.ResponseWriter, r *http.Request) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"triggers": []map[string]any{actionTriggerView("post-login"), actionTriggerView("credentials-exchange")}})
}
func (h *Handlers) GetActionBindings(w http.ResponseWriter, r *http.Request, trigger string) {
	p, err := actionPaging(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if !validActionTrigger(trigger) {
		h.actionError(w, r, store.ErrNotFound)
		return
	}
	bs, err := h.Store.Actions().Bindings(r.Context(), resolved(r).ID, trigger)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	out := []map[string]any{}
	start := min(p.Page*p.PerPage, len(bs))
	for _, b := range bs[start:min(start+p.PerPage, len(bs))] {
		out = append(out, bindingView(b))
	}
	writeJSON(w, 200, map[string]any{"bindings": out, "total": len(bs), "page": p.Page, "per_page": p.PerPage})
}
func (h *Handlers) UpdateActionBindings(w http.ResponseWriter, r *http.Request, trigger string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	if !validActionTrigger(trigger) {
		h.actionError(w, r, store.ErrNotFound)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if len(body) != 1 || body["bindings"] == nil {
		Fail(w, badBody("bindings is required"))
		return
	}
	if err := actionControlValue(body["bindings"]); err != nil {
		Fail(w, err)
		return
	}
	var input []struct {
		Ref *struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"ref"`
		DisplayName *string `json:"display_name,omitempty"`
	}
	if err = decodeStrict(body["bindings"], &input); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	var result []store.BoundVersion
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		old, err := tx.Actions().Bindings(r.Context(), resolved(r).ID, trigger)
		if err != nil {
			return err
		}
		bs := []store.Binding{}
		for _, in := range input {
			if in.Ref == nil || in.Ref.Value == "" {
				return badBody("binding ref type and value are required")
			}
			var a *store.Action
			var b store.Binding
			switch in.Ref.Type {
			case "action_id":
				a, err = tx.Actions().GetAction(r.Context(), resolved(r).ID, in.Ref.Value)
			case "action_name":
				a, err = tx.Actions().GetActionByName(r.Context(), resolved(r).ID, in.Ref.Value)
			case "binding_id":
				for _, v := range old {
					if v.ID == in.Ref.Value {
						b = v.Binding
						a = &v.Action
						break
					}
				}
				if a == nil {
					return store.ErrNotFound
				}
			default:
				return badBody("unsupported binding ref type")
			}
			if err != nil {
				return err
			}
			b.UpdatedAt = h.now()
			b.ActionID = a.ID
			b.Trigger = trigger
			if in.DisplayName != nil {
				b.DisplayName = *in.DisplayName
			} else if b.DisplayName == "" {
				b.DisplayName = a.Name
			}
			bs = append(bs, b)
		}
		if errs := actionsrules.ValidateBindings(trigger, bs); len(errs) > 0 {
			return badBody("%v", errors.Join(errs...))
		}
		result, err = tx.Actions().ReplaceBindings(r.Context(), resolved(r).ID, trigger, bs)
		return err
	})
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	out := []map[string]any{}
	for _, b := range result {
		out = append(out, bindingView(b))
	}
	h.audit(r, "replace Action bindings", "trigger", trigger)
	writeJSON(w, 200, map[string]any{"bindings": out})
}
