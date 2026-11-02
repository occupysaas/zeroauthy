package mgmt

import (
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/url"
	"time"
)

func (h *Handlers) guardianTicket(w http.ResponseWriter, r *http.Request, b map[string]any) {
	uid, _ := b["user_id"].(string)
	u, err := h.getUser(r, uid)
	if err != nil {
		Fail(w, err)
		return
	}
	factor, _ := b["factor"].(string)
	multiple, _ := b["allow_multiple_enrollments"].(bool)
	send, _ := b["send_mail"].(bool)
	locale, _ := b["email_locale"].(string)
	recipient, _ := b["email"].(string)
	if recipient == "" {
		recipient = u.Email
	}
	if send && !mfaEmail(recipient) {
		Fail(w, badBody("a valid email is required"))
		return
	}
	raw := secrets.RandomString(48)
	res, _ := tenant.FromContext(r.Context())
	ticketURL := res.Issuer() + "u/mfa-enroll-ticket?ticket=" + url.QueryEscape(raw)
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), raw, ticketURL))
	err = h.Store.MFA().CreateTicket(r.Context(), &store.EnrollmentTicket{TenantID: u.TenantID, UserID: uid, Hash: secrets.HashToken(raw), Factor: factor, AllowMultiple: multiple, ExpiresAt: h.now().Add(7 * 24 * time.Hour)})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	if send {
		if h.EmailService == nil {
			Fail(w, &Error{Status: 503, Code: "email_unavailable", Message: "Email delivery is unavailable"})
			return
		}
		err = h.EmailService.Send(r.Context(), email.Event{TenantID: u.TenantID, UserID: uid, Template: "enrollment_email", Language: locale, URL: ticketURL, Recipient: recipient})
		if err != nil {
			Fail(w, &Error{Status: 503, Code: "email_unavailable", Message: "Email delivery is unavailable"})
			return
		}
		h.domainEvent(r, "gd_send_email", u, nil, nil)
	}
	h.domainEvent(r, "gd_start_enroll", u, nil, nil)
	logDetails(r, "create Guardian enrollment ticket", "user_id", uid)
	writeJSON(w, 200, map[string]any{"ticket_id": raw, "ticket_url": ticketURL})
}
