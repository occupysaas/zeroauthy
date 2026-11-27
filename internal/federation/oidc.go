package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	oidcclaims "github.com/zeroauthy/zeroauthy/internal/claims"
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
	enterprise := cfg.Channel != "" && (cfg.Strategy == StrategyOIDC || cfg.Strategy == StrategyOkta)
	if enterprise {
		withNonce = cfg.Channel == "front_channel" || cfg.SendNonce
	}
	if in.State == "" || (!enterprise && in.CodeChallenge == "") || in.CallbackURL == "" || (withNonce && in.Nonce == "") {
		return "", fmt.Errorf("federation: incomplete authorization request")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", in.CallbackURL)
	scopes := slices.Clone(cfg.Scopes)
	if cfg.AttrMap != nil {
		for _, scope := range strings.Fields(cfg.AttrMap.UserinfoScope) {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	if cfg.GoogleApps != nil {
		// hd only preselects the account; Exchange enforces the hd claim.
		q.Set("hd", cfg.GoogleApps.Domain)
		if len(in.DirectoryConsent) > 0 {
			scopes = append(scopes, in.DirectoryConsent...)
			q.Set("access_type", "offline")
			q.Set("prompt", "consent")
		}
	}
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", in.State)
	if in.LoginHint != "" {
		q.Set("login_hint", in.LoginHint)
	}
	q.Set("code_challenge", in.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if enterprise {
		if cfg.Channel == "front_channel" {
			q.Set("response_type", "id_token")
			q.Set("response_mode", "form_post")
		}
		if in.Endpoints.PKCEMethod == "" {
			q.Del("code_challenge")
			q.Del("code_challenge_method")
		} else {
			q.Set("code_challenge_method", in.Endpoints.PKCEMethod)
		}
	}
	if withNonce {
		q.Set("nonce", in.Nonce)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// exchangeCode POSTs the authorization code once with exactly one client
// authentication method. It never retries.
func (ps *Providers) exchangeCode(ctx context.Context, tokenURL, method string, in ExchangeInput) (TokenSet, error) {
	body, err := ps.exchangeCodeRaw(ctx, tokenURL, method, in)
	if err != nil {
		return TokenSet{}, err
	}
	return parseTokenResponse(body, ps.now())
}

// exchangeCodeRaw is exchangeCode returning the successful response body.
func (ps *Providers) exchangeCodeRaw(ctx context.Context, tokenURL, method string, in ExchangeInput) ([]byte, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.Code},
		"redirect_uri":  {in.CallbackURL},
		"code_verifier": {in.CodeVerifier},
	}
	if in.Config.Channel != "" && (in.Config.Strategy == StrategyOIDC || in.Config.Strategy == StrategyOkta) && in.Endpoints.PKCEMethod == "" {
		form.Del("code_verifier")
	}
	if in.CodeVerifier == "" && providers.Is(in.Config.Strategy) {
		form.Del("code_verifier")
	}
	if in.Config.Strategy == StrategyApple {
		if in.CodeVerifier == "" {
			form.Del("code_verifier")
		}
		if in.CallbackURL == "" {
			form.Del("redirect_uri")
		}
	}
	if method == authPost {
		form.Set("client_id", in.Config.ClientID)
		form.Set("client_secret", in.ClientSecret)
	} else if method == "private_key_jwt" {
		if in.ClientAssertion == nil {
			return nil, fmt.Errorf("%w: client assertion unavailable", ErrInvalidConfig)
		}
		aud := in.Issuer
		if in.Config.AssertionAud == "token_endpoint" {
			aud = tokenURL
		}
		assertion, e := in.ClientAssertion(aud)
		if e != nil {
			return nil, e
		}
		form.Set("client_id", in.Config.ClientID)
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", assertion)
	} else if method != authBasic {
		return nil, fmt.Errorf("%w: unsupported client authentication", ErrInvalidConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: token endpoint", ErrInvalidConfig)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == authBasic {
		req.SetBasicAuth(url.QueryEscape(in.Config.ClientID), url.QueryEscape(in.ClientSecret))
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: token request: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: token response: %w", ErrProviderResponse, redact(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: token endpoint status %d", ErrProviderResponse, resp.StatusCode)
	}
	return body, nil
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

// googleIssued reports whether cfg's ID tokens come from Google's fixed
// issuer: google-oauth2 and google-apps.
func googleIssued(cfg Config) bool {
	return cfg.Strategy == StrategyGoogle || cfg.Strategy == StrategyGoogleApps
}

func (p oidcProvider) endpoints(in Endpoints, cfg Config) Endpoints {
	if googleIssued(cfg) {
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
	if in.Config.GoogleApps != nil {
		if sub, err = googleAppsSubject(*in.Config.GoogleApps, sub, claims); err != nil {
			return ProviderResult{}, err
		}
	}
	compiled, mapErr := CompileAttrMap(in.Config.AttrMap, in.Config.Strategy, in.Config.Channel)
	if mapErr != nil {
		return ProviderResult{}, mapErr
	}
	var userinfo map[string]any
	legacy := in.Config.AttrMap == nil && (in.Config.Channel != "front_channel")
	_, hasEmail := claims["email"]
	if compiled.NeedsUserInfo() || legacy && !hasEmail && e.UserInfoURL != "" {
		if e.UserInfoURL == "" || tokens.AccessToken == "" {
			return ProviderResult{}, fmt.Errorf("%w: userinfo unavailable", ErrProviderResponse)
		}
		var info map[string]any
		if err := p.ps.getJSON(ctx, e.UserInfoURL, tokens.AccessToken, &info); err != nil {
			return ProviderResult{}, err
		}
		if s, _ := info["sub"].(string); s != sub {
			return ProviderResult{}, fmt.Errorf("%w: userinfo subject differs from the ID token", ErrProviderResponse)
		}
		userinfo = info
		for k, v := range info {
			if _, ok := claims[k]; !ok && legacy {
				claims[k] = v
			}
		}
	}
	profile, err := mappedProfile(in.Config, in.Cache.ConnectionID, sub, claims, userinfo, tokens)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// issuerMatches applies exact issuer equality, with Google's two documented
// issuer forms as the only exception.
func issuerMatches(cfg Config, expected, got string) bool {
	if googleIssued(cfg) && expected == rules.GoogleIssuer {
		return got == rules.GoogleIssuer || got == rules.GoogleIssuerAlias
	}
	return expected != "" && got == expected
}

// validateIDToken checks the ID token: RS256 only, a key from the pinned
// JWKS (never one named by the token), issuer, audience/azp, time with
// skew, nonce, subject and at_hash.
func (ps *Providers) validateIDToken(ctx context.Context, in ExchangeInput, e Endpoints, tokens TokenSet) (map[string]any, error) {
	if in.Config.EncAlg != "" {
		if in.DecryptIDToken == nil {
			return nil, idTokenError("decryption unavailable")
		}
		raw, err := in.DecryptIDToken(tokens.IDToken)
		if err != nil {
			return nil, err
		}
		tokens.IDToken = raw
	}
	allowed := in.Config.IDTokenAlgs
	if googleIssued(in.Config) {
		allowed = []string{"RS256"}
	}
	obj, err := parseIDTokenAlgorithms(tokens.IDToken, allowed)
	if err != nil {
		return nil, err
	}
	issuer := in.Issuer
	if googleIssued(in.Config) && issuer == "" {
		issuer = rules.GoogleIssuer
	}
	key, err := ps.keys.keyForAlgorithm(ctx, in.Cache.with("jwks", issuer, e.JWKSURL), e.JWKSURL, obj.Signatures[0].Header.KeyID, obj.Signatures[0].Header.Algorithm)
	if err != nil {
		return nil, err
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, idTokenError("signature is invalid")
	}
	c, err := decodeIDTokenClaims(payload)
	if err != nil {
		return nil, err
	}
	if iss, _ := c["iss"].(string); !issuerMatches(in.Config, issuer, iss) {
		return nil, idTokenError("issuer mismatch")
	}
	in.IDTokenAlg = obj.Signatures[0].Header.Algorithm
	if err := validateIDTokenClaims(in, tokens, c, ps.exchangeTime(in)); err != nil {
		return nil, err
	}
	return c, nil
}

// profileClaims are the standard claims mapped to root attributes.
var profileClaims = []string{"username", "email", "email_verified", "name", "nickname", "given_name", "family_name", "picture"}

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
	p, err := NormalizeProfile(raw)
	if err != nil {
		return Profile{}, err
	}
	extra := oidcclaims.IdentityClaims(claims)
	if encoded, err := json.Marshal(extra); err == nil && len(encoded) <= maxProfileBytes && len(extra) > 0 {
		p.ProviderData = extra
	}
	return p, nil
}

// oauth2Provider is the generic OAuth 2 code flow: S256 PKCE, one
// client_secret_post exchange, tokens only. The profile comes from the
// connection's script (Task 6).
type oauth2Provider struct{ ps *Providers }

func (p oauth2Provider) AuthorizationURL(in StartInput) (string, error) {
	return authorizationURL(in.Config.AuthorizationURL, in.Config, in, false)
}

func (p oauth2Provider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	if p.ps.scripts == nil {
		// Fail before redeeming the code: nothing could map the profile.
		return ProviderResult{}, ErrScriptUnavailable
	}
	tokens, err := p.ps.exchangeCode(ctx, in.Config.TokenURL, authPost, in)
	if err != nil {
		return ProviderResult{}, err
	}
	profile, err := p.ps.scriptProfile(ctx, in, tokens)
	if err != nil {
		return ProviderResult{}, err
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// googleAppsSubject enforces a google-apps login's Workspace binding: the
// verified ID token's hd claim must equal the connection's domain (an email
// suffix proves nothing; consumer accounts have no hd) and the email must be
// verified. The subject is the lowercase email, or Google's numeric subject
// with map_user_id_to_id.
func googleAppsSubject(g rules.GoogleAppsSettings, sub string, claims map[string]any) (string, error) {
	hd, _ := claims["hd"].(string)
	if g.Domain == "" || !strings.EqualFold(hd, g.Domain) {
		return "", fmt.Errorf("%w: the account is not in the connection's Google Workspace domain", ErrProviderResponse)
	}
	email, _ := claims["email"].(string)
	if email == "" || claims["email_verified"] != true {
		return "", fmt.Errorf("%w: the Google Workspace account has no verified email", ErrProviderResponse)
	}
	if g.MapUserIDToID {
		return sub, nil
	}
	return strings.ToLower(email), nil
}
