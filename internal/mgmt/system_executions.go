package mgmt

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func systemExecutionJSON(ex *store.Execution) map[string]any {
	results := make([]map[string]any, 0, len(ex.Results))
	for _, v := range ex.Results {
		lines := append([]string{}, v.Logs...)
		result := map[string]any{"action_name": v.ActionName, "started_at": v.StartedAt, "ended_at": v.EndedAt, "logs": lines}
		if v.ActionID != "" {
			result["action_id"] = v.ActionID
		}
		if v.JobID != "" {
			result["job_id"] = v.JobID
			result["job_attempt"] = v.JobAttempt
		}
		if v.ErrorID != "" || v.ErrorMsg != "" {
			result["error"] = map[string]string{"id": v.ErrorID, "message": v.ErrorMsg}
		}
		results = append(results, result)
	}
	return map[string]any{"id": ex.ID, "trigger_id": ex.Trigger, "status": ex.Status, "results": results, "created_at": ex.CreatedAt, "updated_at": ex.UpdatedAt}
}
func (h *Handlers) executionTenant(w http.ResponseWriter, r *http.Request, name string) *store.Tenant {
	tn, err := h.Store.Tenants().GetByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return nil
	}
	if err != nil {
		Fail(w, internalError(h, r, "read execution tenant", err))
		return nil
	}
	return tn
}
func (h *Handlers) executionAvailable(w http.ResponseWriter, r *http.Request) bool {
	if capability, ok := h.Store.(store.LogsSupporter); ok {
		if err := capability.CheckLogsSupport(r.Context()); err != nil {
			h.logError(w, r, err)
			return false
		}
	}
	return true
}
func (h *Handlers) executionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrActionsUnavailable) || errors.Is(err, store.ErrLogsUnavailable) {
		Fail(w, errLogsUnavailable)
		return
	}
	h.actionError(w, r, err)
}

func (h *Handlers) GetTenantActionExecutions(w http.ResponseWriter, r *http.Request, name string, _ mgmtapi.GetTenantActionExecutionsParams) {
	if !h.executionAvailable(w, r) {
		return
	}
	q := r.URL.Query()
	f := store.ExecutionFilter{After: q.Get("after"), Trigger: q.Get("trigger"), Action: q.Get("action")}
	for key, v := range q {
		if len(v) != 1 || (key != "after" && key != "trigger" && key != "action" && key != "take") {
			Fail(w, badBody("invalid execution query"))
			return
		}
	}
	if value := q.Get("take"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			Fail(w, badBody("take must be a positive integer"))
			return
		}
		f.Take = min(n, 100)
	}
	tn := h.executionTenant(w, r, name)
	if tn == nil {
		return
	}
	executions, err := h.Store.Actions().ListExecutions(r.Context(), tn.ID, f)
	if err != nil {
		h.executionError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(executions))
	for i := range executions {
		out = append(out, systemExecutionJSON(&executions[i]))
	}
	writeJSON(w, 200, out)
}
func (h *Handlers) GetTenantActionExecution(w http.ResponseWriter, r *http.Request, name, id string) {
	if !h.executionAvailable(w, r) {
		return
	}
	tn := h.executionTenant(w, r, name)
	if tn == nil {
		return
	}
	ex, err := h.Store.Actions().GetExecution(r.Context(), tn.ID, id)
	if err != nil {
		h.executionError(w, r, err)
		return
	}
	writeJSON(w, 200, systemExecutionJSON(ex))
}
