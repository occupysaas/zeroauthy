package protection

import (
	"context"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (v *providerVerifier) friendlyCaptcha(ctx context.Context, c CaptchaChallenge, response string, p store.CAPTCHAProvider) error {
	if p.Secret == "" || p.SiteKey != c.SiteKey {
		return ErrCaptchaUnavailable
	}
	out, err := v.siteVerify(ctx, "https://api.friendlycaptcha.com/api/v1/siteverify", url.Values{"secret": {p.Secret}, "solution": {response}, "sitekey": {p.SiteKey}})
	if err != nil {
		return err
	}
	// Friendly v1 binds the solution with the submitted sitekey and does not
	// promise a hostname in its response. Validate it if one is returned.
	if !out.Success || (out.Hostname != "" && out.Hostname != c.Hostname) {
		return ErrCaptchaInvalid
	}
	return nil
}
