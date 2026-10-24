package protection

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type siteResult struct {
	ErrorCodes []string `json:"error-codes"`
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
}

func (v *providerVerifier) siteVerify(ctx context.Context, endpoint string, values url.Values) (siteResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return siteResult{}, ErrCaptchaUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out siteResult
	err = v.request(req, &out)
	if err == nil && !out.Success {
		err = out.failure()
	}
	return out, err
}
func (v *providerVerifier) recaptchaV2(ctx context.Context, c CaptchaChallenge, response string, p store.CAPTCHAProvider) error {
	if p.Secret == "" || p.SiteKey != c.SiteKey {
		return ErrCaptchaUnavailable
	}
	out, err := v.siteVerify(ctx, "https://www.google.com/recaptcha/api/siteverify", url.Values{"secret": {p.Secret}, "response": {response}})
	if err != nil {
		return err
	}
	if !out.Success || out.Hostname != c.Hostname {
		return ErrCaptchaInvalid
	}
	return nil
}

// Only recognized user-proof errors count as risk. Unknown, configuration and
// service errors fail closed as unavailable; provider details never escape.
func (r siteResult) failure() error {
	if len(r.ErrorCodes) == 0 {
		return ErrCaptchaInvalid
	}
	for _, code := range r.ErrorCodes {
		switch code {
		case "missing-input-response", "invalid-input-response", "timeout-or-duplicate", "invalid-or-already-seen-response", "expired-input-response", "missing-input-solution", "invalid-input-solution", "solution_missing", "solution_invalid", "solution_timeout", "solution_duplicate":
		default:
			return ErrCaptchaUnavailable
		}
	}
	return ErrCaptchaInvalid
}
