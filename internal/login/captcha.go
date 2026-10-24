package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

func (h *Handlers) captchaAttempt(r *http.Request, res tenant.Resolved, flow string) protection.Attempt {
	return protection.Attempt{Tenant: res.Tenant, Flow: flow, IP: httpx.ClientIP(r, h.TrustProxyHeaders)}
}
func (h *Handlers) prepareCaptcha(r *http.Request, res tenant.Resolved, view *ui.Tenant, flow, id string) (*protection.CaptchaChallenge, error) {
	required, err := h.protectionService().RequireChallenge(r.Context(), h.captchaAttempt(r, res, flow))
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, nil
	}
	issuer, _ := url.Parse(res.Issuer())
	c, err := h.protectionService().Challenge(r.Context(), res.Tenant.ID, flow, id, issuer.Hostname())
	if err != nil {
		return nil, err
	}
	view.Captcha = &ui.Captcha{Provider: c.ProviderID, SiteKey: c.SiteKey, Action: c.Action}
	return &c, nil
}
func (h *Handlers) submitCaptcha(r *http.Request, res tenant.Resolved, view *ui.Tenant, flow, id, attemptID string) error {
	c, err := h.prepareCaptcha(r, res, view, flow, id)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	field := "g-recaptcha-response"
	switch c.ProviderID {
	case "hcaptcha":
		field = "h-captcha-response"
	case "friendly_captcha":
		field = "frc-captcha-solution"
	}
	err = h.protectionService().VerifyChallenge(r.Context(), *c, r.PostForm.Get(field))
	if errors.Is(err, protection.ErrCaptchaInvalid) {
		if riskErr := h.protectionService().RecordFailure(r.Context(), h.captchaAttempt(r, res, flow), attemptID); riskErr != nil {
			return riskErr
		}
	}
	return err
}
func captchaFailure(err error) (int, string) {
	if errors.Is(err, protection.ErrCaptchaInvalid) {
		return http.StatusBadRequest, i18n.KeyCaptchaInvalid
	}
	return http.StatusServiceUnavailable, i18n.KeyCaptchaUnavailable
}
func (h *Handlers) captchaPage(w http.ResponseWriter, r *http.Request, f *flow, kind string) bool {
	if _, err := h.prepareCaptcha(r, f.res, &f.view, kind, f.txn.ID); err != nil {
		status, key := captchaFailure(err)
		ui.RenderError(w, status, f.view, f.view.L.T(key))
		return false
	}
	return true
}
func (h *Handlers) recordFailure(r *http.Request, res tenant.Resolved, kind, id string, err error) error {
	if !protection.QualifyingFailure(kind, err) {
		return nil
	}
	return h.protectionService().RecordFailure(r.Context(), h.captchaAttempt(r, res, kind), id)
}
