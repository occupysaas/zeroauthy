package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Native token types (Plan 39b, D-0180). Facebook's is Auth0's documented
// session-info type; Auth0 documents no Google type, so zeroauthy's is local
// (SP-3).
const (
	NativeFacebookSubjectType = "http://auth0.com/oauth/token-type/facebook-info-session-access-token"
	NativeGoogleSubjectType   = "http://auth0.com/oauth/token-type/google-id-token"
)

// maxFacebookUserProfile bounds the posted user_profile JSON.
const maxFacebookUserProfile = 2048

// facebookDebugTokenPath is Graph's token inspection endpoint, on the
// facebook descriptor's Graph version.
const facebookDebugTokenURL = "https://graph.facebook.com/v24.0/debug_token"

// FacebookUser is the untrusted user_profile a native Facebook app posts.
type FacebookUser struct {
	ID, Name, FirstName, LastName, Email string
}

// ParseFacebookUser reads a bounded user_profile object of strings.
func ParseFacebookUser(raw string) (*FacebookUser, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxFacebookUserProfile {
		return nil, fmt.Errorf("%w: user_profile is larger than %d bytes", ErrProfile, maxFacebookUserProfile)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: user_profile must be a JSON object", ErrProfile)
	}
	u := &FacebookUser{}
	for k, dst := range map[string]*string{"id": &u.ID, "name": &u.Name, "first_name": &u.FirstName, "last_name": &u.LastName, "email": &u.Email} {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		s, err := profileString(k, v, 300)
		if err != nil {
			return nil, err
		}
		*dst = s
	}
	return u, nil
}

// NativeGoogleProfile verifies a native Google ID token (LR39b-11): RS256
// with a key from Google's pinned JWKS, Google's issuer, aud equal to the
// connection's client_id (an Android azp is allowed), time with skew and a
// subject. Native tokens carry no nonce. No upstream token is stored.
func (ps *Providers) NativeGoogleProfile(ctx context.Context, cfg Config, cache CacheKey, idToken string) (ProviderResult, error) {
	if cfg.Strategy != StrategyGoogle || idToken == "" {
		return ProviderResult{}, ErrConnectionUnusable
	}
	e, issuer := ps.google()
	in := ExchangeInput{Config: cfg, Cache: cache, Endpoints: e, Issuer: issuer, Now: ps.now(), GoogleNative: true}
	claims, err := ps.validateIDToken(ctx, in, e, TokenSet{IDToken: idToken})
	if err != nil {
		return ProviderResult{}, err
	}
	sub, _ := claims["sub"].(string)
	profile, err := mappedProfile(cfg, cache.ConnectionID, sub, claims, nil, TokenSet{})
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	return ProviderResult{Profile: profile}, nil
}

// NativeFacebookProfile checks a session-info token with Graph's debug_token
// using the connection's app access token: it must be a valid USER token of
// the connection's app. The subject is debug_token's user_id. user_profile,
// posted by the app, must name the same user; its email is never verified
// (LR39b-11). No upstream token is stored.
func (ps *Providers) NativeFacebookProfile(ctx context.Context, cfg Config, appSecret, token string, up *FacebookUser) (ProviderResult, error) {
	if cfg.Strategy != "facebook" || token == "" || appSecret == "" {
		return ProviderResult{}, ErrConnectionUnusable
	}
	target := ps.socialURL("facebook", facebookDebugTokenURL) + "?input_token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: debug_token URL", ErrInvalidConfig)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.ClientID+"|"+appSecret)
	resp, err := ps.client.Do(req)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: facebook debug_token request: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ProviderResult{}, fmt.Errorf("%w: facebook debug_token response", ErrProviderResponse)
	}
	var out struct {
		Data struct {
			AppID   string `json:"app_id"`
			Type    string `json:"type"`
			IsValid bool   `json:"is_valid"`
			UserID  string `json:"user_id"`
		} `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if dec.Decode(&out) != nil {
		return ProviderResult{}, fmt.Errorf("%w: facebook debug_token is malformed", ErrProviderResponse)
	}
	d := out.Data
	if !d.IsValid || d.AppID == "" || d.AppID != cfg.ClientID || d.UserID == "" || (d.Type != "" && !strings.EqualFold(d.Type, "USER")) {
		return ProviderResult{}, fmt.Errorf("%w: facebook token is not a valid user token of this app", ErrProviderResponse)
	}
	if err := ValidateSubject(d.UserID); err != nil {
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	p := Profile{Subject: d.UserID}
	if up != nil {
		if up.ID != "" && up.ID != d.UserID {
			return ProviderResult{}, fmt.Errorf("%w: user_profile names another user", ErrProviderResponse)
		}
		set := func(s string) *string {
			if s == "" {
				return nil
			}
			return &s
		}
		p.Name, p.GivenName, p.FamilyName = set(up.Name), set(up.FirstName), set(up.LastName)
		if up.Email != "" && len(up.Email) <= 254 {
			unverified := false
			p.Email, p.EmailVerified = set(up.Email), &unverified
		}
	}
	return ProviderResult{Profile: p}, nil
}
