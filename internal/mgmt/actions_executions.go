package mgmt

import (
	"encoding/json"
	"net/http"
)

func (h *Handlers) TestAction(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if len(body) != 1 || body["payload"] == nil {
		Fail(w, badBody("payload is required"))
		return
	}
	var payload map[string]json.RawMessage
	if err := decodeStrict(body["payload"], &payload); err != nil {
		Fail(w, badBody("payload must be an object"))
		return
	}
	a, err := h.Store.Actions().GetAction(r.Context(), resolved(r).ID, id)
	if err == nil {
		err = h.recoverAction(r.Context(), a)
	}
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	if h.Actions == nil {
		WriteError(w, 503, "actions_unavailable", "The Actions runtime is unavailable")
		return
	}
	out, err := h.Actions.Test(r.Context(), resolved(r).ID, id, body["payload"])
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"payload": out})
}
func (h *Handlers) GetActionExecution(w http.ResponseWriter, r *http.Request, id string) {
	if err := actionQuery(r); err != nil {
		Fail(w, err)
		return
	}
	e, err := h.Store.Actions().GetExecution(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.actionError(w, r, err)
		return
	}
	results := []map[string]any{}
	for _, v := range e.Results {
		r := map[string]any{"action_name": v.ActionName, "started_at": v.StartedAt, "ended_at": v.EndedAt}
		if v.ErrorID != "" || v.ErrorMsg != "" {
			r["error"] = map[string]any{"id": v.ErrorID, "message": v.ErrorMsg}
		}
		results = append(results, r)
	}
	writeJSON(w, 200, map[string]any{"id": e.ID, "trigger_id": e.Trigger, "status": e.Status, "results": results, "created_at": e.CreatedAt, "updated_at": e.UpdatedAt})
}
