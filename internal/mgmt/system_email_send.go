package mgmt

import (
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (h *Handlers) TestEmail(w http.ResponseWriter, r *http.Request, tenantName string) {
	t, c, ok := h.systemEmailTarget(w, r, tenantName)
	if !ok {
		return
	}
	if h.EmailService == nil {
		WriteError(w, http.StatusServiceUnavailable, "email_unavailable", "Email service is unavailable")
		return
	}
	body, err := readSystemEmailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for key := range body {
		if key != "template" {
			Fail(w, badBody("unknown property"))
			return
		}
	}
	name, err := rawString(body["template"])
	if err != nil || !emailrules.KnownTemplate(name) {
		Fail(w, badBody("template must name a supported email template"))
		return
	}
	policy, err := h.EmailService.Resolve(r.Context(), t.ID, name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return
	}
	if policy.Template == nil || !policy.Enabled {
		Fail(w, errSystemEmailTemplate)
		return
	}
	systemTenant, err := h.Store.Tenants().GetByName(r.Context(), tenant.SystemName)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return
	}
	operator, err := h.Store.Users().Get(r.Context(), systemTenant.ID, c.UserID)
	if err != nil || !operator.EmailVerified || operator.Email == "" {
		WriteError(w, http.StatusForbidden, "insufficient_scope", "A verified operator email address is required")
		return
	}
	if !h.claimSystemEmail(w, r, t, c, "test", 10*time.Minute, 3) {
		return
	}
	if err = h.EmailService.SendTest(r.Context(), t.ID, name, operator.Email); err != nil {
		h.auditSystemEmail(r, t, "test email", name, "failed")
		WriteError(w, http.StatusBadGateway, "email_delivery_failed", "The email provider did not accept the test message")
		return
	}
	h.auditSystemEmail(r, t, "test email", name, "accepted")
	w.WriteHeader(http.StatusNoContent)
}
