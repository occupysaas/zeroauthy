package dbconn

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (h *Handlers) directChallenge(w http.ResponseWriter, r *http.Request, res tenant.Resolved, flow string, receipt store.ProtectionReceipt) bool {
	required, err := h.protectionService().RequireChallenge(r.Context(), protection.Attempt{Tenant: res.Tenant, Flow: flow, IP: httpx.ClientIP(r, h.TrustProxyHeaders)})
	if err == nil && !required {
		return false
	}
	if finishErr := h.protectionService().Finish(r.Context(), receipt, "refund"); finishErr != nil {
		h.internal(w, r, "protection completion", finishErr)
		return true
	}
	if err != nil {
		h.internal(w, r, "challenge policy", err)
		return true
	}
	writeErr(w, http.StatusUnauthorized, "requires_verification", "Complete verification using interactive web login.")
	return true
}
func (h *Handlers) recordFailure(r *http.Request, res tenant.Resolved, flow, id string, err error) error {
	if !protection.QualifyingFailure(flow, err) {
		return nil
	}
	return h.protectionService().RecordFailure(r.Context(), protection.Attempt{Tenant: res.Tenant, Flow: flow, IP: httpx.ClientIP(r, h.TrustProxyHeaders)}, id)
}
