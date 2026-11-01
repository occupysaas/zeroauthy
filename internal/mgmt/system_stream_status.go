package mgmt

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// GetTenantLogStreamStatus is the console's delivery-only projection. Sink
// configuration and sealed credentials are deliberately never decoded here.
func (h *Handlers) GetTenantLogStreamStatus(w http.ResponseWriter, r *http.Request, name string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	tn := h.executionTenant(w, r, name)
	if tn == nil {
		return
	}
	streams, err := repo.ListLogStreams(r.Context(), tn.ID)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(streams))
	for _, s := range streams {
		out = append(out, streamStatusView(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func streamStatusView(s store.LogStream) map[string]any {
	// A legacy/external driver cannot inject arbitrary error text into this
	// diagnostics response. Delivery workers store only these fixed classes.
	errorClass := s.LastErrorClass
	switch errorClass {
	case "", "http_4xx", "http_5xx", "blocked_address", "timeout", "dns", "tls", "refused":
	default:
		errorClass = "unknown"
	}
	out := map[string]any{"id": s.ID, "status": s.Status, "failures": s.Failures, "last_error_class": errorClass}
	if !s.LastSuccessAt.IsZero() {
		out["last_success_at"] = s.LastSuccessAt.UTC()
	}
	if !s.NextAt.IsZero() {
		out["next_at"] = s.NextAt.UTC()
	}
	return out
}
