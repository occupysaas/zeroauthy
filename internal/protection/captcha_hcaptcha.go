package protection

import (
	"context"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (v *providerVerifier) hcaptcha(ctx context.Context, c CaptchaChallenge, response string, p store.CAPTCHAProvider) error {
	if p.Secret == "" || p.SiteKey != c.SiteKey {
		return ErrCaptchaUnavailable
	}
	out, err := v.siteVerify(ctx, "https://api.hcaptcha.com/siteverify", url.Values{"secret": {p.Secret}, "response": {response}, "sitekey": {p.SiteKey}})
	if err != nil {
		return err
	}
	if !out.Success || out.Hostname != c.Hostname {
		return ErrCaptchaInvalid
	}
	return nil
}
