package protection

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (v *providerVerifier) enterprise(ctx context.Context, c CaptchaChallenge, response string, p store.RecaptchaEnterpriseProvider) error {
	if p.APIKey == "" || p.ProjectID == "" || p.SiteKey != c.SiteKey {
		return ErrCaptchaUnavailable
	}
	raw, _ := json.Marshal(map[string]any{"event": map[string]string{"token": response, "siteKey": p.SiteKey, "expectedAction": c.Action}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://recaptchaenterprise.googleapis.com/v1/projects/"+url.PathEscape(p.ProjectID)+"/assessments?"+url.Values{"key": {p.APIKey}}.Encode(), bytes.NewReader(raw))
	if err != nil {
		return ErrCaptchaUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		TokenProperties struct {
			Valid    bool   `json:"valid"`
			Hostname string `json:"hostname"`
			Action   string `json:"action"`
		} `json:"tokenProperties"`
		Event struct {
			SiteKey string `json:"siteKey"`
		} `json:"event"`
	}
	if err := v.request(req, &out); err != nil {
		return err
	}
	if !out.TokenProperties.Valid || out.TokenProperties.Hostname != c.Hostname || out.TokenProperties.Action != c.Action || out.Event.SiteKey != c.SiteKey {
		return ErrCaptchaInvalid
	}
	return nil
}
