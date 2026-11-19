package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PushAuthorization sends the complete authorization request over the guarded
// HTTPS client. The returned URI is an opaque browser parameter, never fetched.
func (ps *Providers) PushAuthorization(ctx context.Context, authorization string, in ExchangeInput) (string, error) {
	u, e := url.Parse(authorization)
	if e != nil {
		return "", ErrInvalidConfig
	}
	form := u.Query()
	method := in.Endpoints.TokenAuthMethod
	switch method {
	case authPost:
		form.Set("client_secret", in.ClientSecret)
	case authBasic:
	case "private_key_jwt":
		if in.ClientAssertion == nil {
			return "", ErrInvalidConfig
		}
		aud := in.Issuer
		if in.Config.AssertionAud == "token_endpoint" {
			aud = in.Endpoints.TokenURL
		}
		a, e := in.ClientAssertion(aud)
		if e != nil {
			return "", e
		}
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", a)
	default:
		return "", ErrInvalidConfig
	}
	req, e := http.NewRequestWithContext(ctx, "POST", in.Endpoints.PAREndpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return "", ErrInvalidConfig
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == authBasic {
		req.SetBasicAuth(url.QueryEscape(in.Config.ClientID), url.QueryEscape(in.ClientSecret))
	}
	resp, e := ps.client.Do(req)
	if e != nil {
		return "", fmt.Errorf("%w: PAR transport: %w", ErrProviderResponse, redact(e))
	}
	body, e := readAll(resp)
	if e != nil {
		return "", e
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("%w: PAR status %d", ErrProviderResponse, resp.StatusCode)
	}
	var result struct {
		URI     string      `json:"request_uri"`
		Expires json.Number `json:"expires_in"`
	}
	if json.Unmarshal(body, &result) != nil || result.URI == "" || len(result.URI) > 2048 {
		return "", fmt.Errorf("%w: invalid PAR response", ErrProviderResponse)
	}
	ttl, e := result.Expires.Int64()
	if e != nil || ttl <= 0 {
		return "", fmt.Errorf("%w: invalid PAR expiry", ErrProviderResponse)
	}
	u.RawQuery = url.Values{"client_id": {in.Config.ClientID}, "request_uri": {result.URI}}.Encode()
	return u.String(), nil
}
