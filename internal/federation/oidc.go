package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// Validation limits (spec §5).
const (
	clockSkew     = 60 * time.Second
	maxTokenBytes = 65536
)

// authorizationURL builds the provider redirect: the configured endpoint
// (its non-reserved query kept) plus the code-flow parameters with S256 PKCE.
func authorizationURL(endpoint string, cfg Config, in StartInput, withNonce bool) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || endpoint == "" {
		return "", fmt.Errorf("%w: authorization endpoint", ErrInvalidConfig)
	}
	if in.State == "" || in.CodeChallenge == "" || in.CallbackURL == "" || (withNonce && in.Nonce == "") {
		return "", fmt.Errorf("federation: incomplete authorization request")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", in.CallbackURL)
	q.Set("scope", strings.Join(cfg.Scopes, " "))
	q.Set("state", in.State)
	q.Set("code_challenge", in.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if withNonce {
		q.Set("nonce", in.Nonce)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// exchangeCode POSTs the authorization code once with exactly one client
// authentication method. It never retries.
func (ps *Providers) exchangeCode(ctx context.Context, tokenURL, method string, in ExchangeInput) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.Code},
		"redirect_uri":  {in.CallbackURL},
		"code_verifier": {in.CodeVerifier},
	}
	if method == authPost {
		form.Set("client_id", in.Config.ClientID)
		form.Set("client_secret", in.ClientSecret)
	} else if method != authBasic {
		return TokenSet{}, fmt.Errorf("%w: unsupported client authentication", ErrInvalidConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token endpoint", ErrInvalidConfig)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == authBasic {
		req.SetBasicAuth(url.QueryEscape(in.Config.ClientID), url.QueryEscape(in.ClientSecret))
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token request: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token response: %w", ErrProviderResponse, redact(err))
	}
	if resp.StatusCode != http.StatusOK {
		return TokenSet{}, fmt.Errorf("%w: token endpoint status %d", ErrProviderResponse, resp.StatusCode)
	}
	return parseTokenResponse(body, ps.now())
}

func parseTokenResponse(body []byte, now time.Time) (TokenSet, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return TokenSet{}, fmt.Errorf("%w: malformed token response", ErrProviderResponse)
	}
	if _, isErr := m["error"]; isErr {
		return TokenSet{}, fmt.Errorf("%w: token endpoint returned an error", ErrProviderResponse)
	}
	str := func(k string, required bool) (string, error) {
		v, ok := m[k]
		if !ok || v == nil {
			if required {
				return "", fmt.Errorf("%w: token response lacks %s", ErrProviderResponse, k)
			}
			return "", nil
		}
		s, isStr := v.(string)
		if !isStr || (required && s == "") || len(s) > maxTokenBytes {
			return "", fmt.Errorf("%w: token response %s is invalid", ErrProviderResponse, k)
		}
		return s, nil
	}
	var t TokenSet
	var err error
	if t.AccessToken, err = str("access_token", true); err != nil {
		return TokenSet{}, err
	}
	if t.TokenType, err = str("token_type", true); err != nil {
		return TokenSet{}, err
	}
	if t.RefreshToken, err = str("refresh_token", false); err != nil {
		return TokenSet{}, err
	}
	if t.IDToken, err = str("id_token", false); err != nil {
		return TokenSet{}, err
	}
	if t.Scope, err = str("scope", false); err != nil {
		return TokenSet{}, err
	}
	switch v := m["expires_in"].(type) {
	case nil:
	case json.Number:
		n, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil || n < 0 {
			return TokenSet{}, fmt.Errorf("%w: token response expires_in is invalid", ErrProviderResponse)
		}
		t.ExpiresIn = n
		t.ExpiresAt = now.Add(time.Duration(n) * time.Second)
	case string:
		// Some providers send it quoted.
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return TokenSet{}, fmt.Errorf("%w: token response expires_in is invalid", ErrProviderResponse)
		}
		t.ExpiresIn = n
		t.ExpiresAt = now.Add(time.Duration(n) * time.Second)
	default:
		return TokenSet{}, fmt.Errorf("%w: token response expires_in is invalid", ErrProviderResponse)
	}
	return t, nil
}

// oidcProvider implements Google and back-channel OIDC: code exchange, then
// a validated RS256 ID token, then optional UserInfo.
type oidcProvider struct{ ps *Providers }

func (p oidcProvider) endpoints(in Endpoints, cfg Config) Endpoints {
	if cfg.Strategy == StrategyGoogle {
		g := GoogleEndpoints()
		if in.JWKSURL != "" { // a fixture may pin its own endpoints
			return in
		}
		return g
	}
	return in
}

func (p oidcProvider) AuthorizationURL(in StartInput) (string, error) {
	return authorizationURL(p.endpoints(in.Endpoints, in.Config).AuthorizationURL, in.Config, in, true)
}

func (p oidcProvider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	e := p.endpoints(in.Endpoints, in.Config)
	tokens, err := p.ps.exchangeCode(ctx, e.TokenURL, e.TokenAuthMethod, in)
	if err != nil {
		return ProviderResult{}, err
	}
	if tokens.IDToken == "" {
		return ProviderResult{}, fmt.Errorf("%w: token response lacks id_token", ErrProviderResponse)
	}
	claims, err := p.ps.validateIDToken(ctx, in, e, tokens)
	if err != nil {
		return ProviderResult{}, err
	}
	sub, _ := claims["sub"].(string)
	if _, hasEmail := claims["email"]; !hasEmail && e.UserInfoURL != "" {
		var info map[string]any
		if err := p.ps.getJSON(ctx, e.UserInfoURL, tokens.AccessToken, &info); err != nil {
			return ProviderResult{}, err
		}
		if s, _ := info["sub"].(string); s != sub {
			return ProviderResult{}, fmt.Errorf("%w: userinfo subject differs from the ID token", ErrProviderResponse)
		}
		for k, v := range info {
			if _, ok := claims[k]; !ok {
				claims[k] = v
			}
		}
	}
	profile, err := profileFromClaims(sub, claims)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// issuerMatches applies exact issuer equality, with Google's two documented
// issuer forms as the only exception.
func issuerMatches(cfg Config, expected, got string) bool {
	if cfg.Strategy == StrategyGoogle && expected == rules.GoogleIssuer {
		return got == rules.GoogleIssuer || got == rules.GoogleIssuerAlias
	}
	return expected != "" && got == expected
}

// validateIDToken checks the ID token: RS256 only, a key from the pinned
// JWKS (never one named by the token), issuer, audience/azp, time with
// skew, nonce, subject and at_hash.
func (ps *Providers) validateIDToken(ctx context.Context, in ExchangeInput, e Endpoints, tokens TokenSet) (map[string]any, error) {
	fail := func(what string) (map[string]any, error) {
		return nil, fmt.Errorf("%w: ID token %s", ErrProviderResponse, what)
	}
	obj, err := jose.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(obj.Signatures) != 1 {
		return fail("is not a single RS256 JWS")
	}
	h := obj.Signatures[0].Header
	if h.JSONWebKey != nil || h.ExtraHeaders["jku"] != nil || h.ExtraHeaders["x5u"] != nil || h.ExtraHeaders["x5c"] != nil {
		return fail("names its own key")
	}
	issuer := in.Issuer
	if in.Config.Strategy == StrategyGoogle && issuer == "" {
		issuer = rules.GoogleIssuer
	}
	key, err := ps.keys.key(ctx, in.Cache.with("jwks", issuer, e.JWKSURL), e.JWKSURL, h.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return fail("signature is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var c map[string]any
	if err := dec.Decode(&c); err != nil {
		return fail("claims are malformed")
	}
	if iss, _ := c["iss"].(string); !issuerMatches(in.Config, issuer, iss) {
		return fail("issuer mismatch")
	}
	var aud []string
	switch v := c["aud"].(type) {
	case string:
		aud = []string{v}
	case []any:
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				return fail("audience is malformed")
			}
			aud = append(aud, s)
		}
	default:
		return fail("audience missing")
	}
	hasClient := false
	for _, a := range aud {
		hasClient = hasClient || a == in.Config.ClientID
	}
	azp, hasAzp := c["azp"].(string)
	if !hasClient || (len(aud) > 1 && !hasAzp) || (hasAzp && azp != in.Config.ClientID) {
		return fail("audience mismatch")
	}
	now := in.Now
	if now.IsZero() {
		now = ps.now()
	}
	exp, okExp := numericDate(c["exp"])
	iat, okIat := numericDate(c["iat"])
	if !okExp || !okIat || !now.Before(exp.Add(clockSkew)) || iat.After(now.Add(clockSkew)) {
		return fail("is expired or not yet valid")
	}
	if nonce, _ := c["nonce"].(string); in.Nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(in.Nonce)) != 1 {
		return fail("nonce mismatch")
	}
	if sub, _ := c["sub"].(string); ValidateSubject(sub) != nil {
		return fail("subject is missing or invalid")
	}
	if v, present := c["at_hash"]; present {
		s, _ := v.(string)
		sum := sha256.Sum256([]byte(tokens.AccessToken))
		if s == "" || subtle.ConstantTimeCompare([]byte(s), []byte(base64.RawURLEncoding.EncodeToString(sum[:16]))) != 1 {
			return fail("at_hash mismatch")
		}
	}
	return c, nil
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// profileClaims are the standard claims mapped to root attributes.
var profileClaims = []string{"email", "email_verified", "name", "nickname", "given_name", "family_name", "picture"}

// profileFromClaims maps verified claims to a Profile. An optional claim of
// the wrong type or shape is dropped rather than failing the login; the
// subject is required.
func profileFromClaims(sub string, claims map[string]any) (Profile, error) {
	m := map[string]any{"user_id": sub}
	for _, k := range profileClaims {
		v, ok := claims[k]
		if !ok {
			continue
		}
		probe, _ := json.Marshal(map[string]any{"user_id": sub, k: v})
		if _, err := NormalizeProfile(probe); err == nil {
			m[k] = v
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Profile{}, err
	}
	return NormalizeProfile(raw)
}

// oauth2Provider is the generic OAuth 2 code flow: S256 PKCE, one
// client_secret_post exchange, tokens only. The profile comes from the
// connection's script (Task 6).
type oauth2Provider struct{ ps *Providers }

func (p oauth2Provider) AuthorizationURL(in StartInput) (string, error) {
	return authorizationURL(in.Config.AuthorizationURL, in.Config, in, false)
}

func (p oauth2Provider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	tokens, err := p.ps.exchangeCode(ctx, in.Config.TokenURL, authPost, in)
	if err != nil {
		return ProviderResult{}, err
	}
	return ProviderResult{Tokens: tokens}, nil
}
