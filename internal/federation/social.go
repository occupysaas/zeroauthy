package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// maxSocialPictureBytes bounds a mapped picture URL.
const maxSocialPictureBytes = 2048

// socialHook is a provider quirk named by a descriptor (D-0180 LR39b-2). Each
// function is optional.
type socialHook struct {
	// begin adjusts the endpoints at login start (per-shop hosts) or refuses
	// the login.
	begin func(d *providers.Descriptor, cfg Config, loginHint string, e *Endpoints) error
	// profileURL picks the profile URL from the token response.
	profileURL func(e Endpoints, token map[string]any) (string, error)
	// decorate adds request parameters to every profile call.
	decorate func(req *http.Request, accessToken, clientSecret string)
	// after completes the profile with extra provider calls.
	after func(ctx context.Context, ps *Providers, d *providers.Descriptor, in ExchangeInput, t TokenSet, p *Profile) error
}

// socialHooks are the registered hook implementations, by descriptor hook name.
var socialHooks = map[string]socialHook{}

// WithSocialFixture points every descriptor provider at a local harness:
// each provider URL becomes base + "/" + strategy + its path and query. Tests
// and the E2E harness only; no configuration or API reaches it.
func (ps *Providers) WithSocialFixture(base string) *Providers {
	ps.socialFix = strings.TrimSuffix(base, "/")
	return ps
}

// socialURL applies the fixture rewrite, if any.
func (ps *Providers) socialURL(strategy, raw string) string {
	if ps.socialFix == "" || raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	out := ps.socialFix + "/" + strategy + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// SocialEndpoints returns the endpoints of a descriptor strategy for a login
// started with loginHint. They are sealed in the attempt; Exchange uses only
// the sealed copy.
func (ps *Providers) SocialEndpoints(cfg Config, loginHint string) (Endpoints, error) {
	d, ok := providers.Get(cfg.Strategy)
	if !ok {
		return Endpoints{}, ErrConnectionUnusable
	}
	return ps.socialEndpoints(d, cfg, loginHint)
}

// socialEndpoints builds d's endpoints, runs its begin hook and applies the
// fixture rewrite.
func (ps *Providers) socialEndpoints(d *providers.Descriptor, cfg Config, loginHint string) (Endpoints, error) {
	if r := d.Retired; r != nil {
		// Stored and returned like any connection; never signed in to
		// (LR39d-3). The reason is operator-safe text from the descriptor.
		return Endpoints{}, fmt.Errorf("%w: %s sign-in was retired on %s: %s", ErrConnectionUnusable, d.DisplayName, r.Date, r.Reason)
	}
	e := ps.socialEndpointsFor(d, cfg, loginHint)
	if h, ok := socialHooks[d.Hook]; ok && h.begin != nil {
		if err := h.begin(d, cfg, loginHint, &e); err != nil {
			return Endpoints{}, err
		}
	}
	e.AuthorizationURL = ps.socialURL(d.Strategy, e.AuthorizationURL)
	e.TokenURL = ps.socialURL(d.Strategy, e.TokenURL)
	e.UserInfoURL = ps.socialURL(d.Strategy, e.UserInfoURL)
	return e, nil
}

func (ps *Providers) socialEndpointsFor(d *providers.Descriptor, cfg Config, _ string) Endpoints {
	e := Endpoints{AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, UserInfoURL: d.ProfileURL, TokenAuthMethod: authPost}
	if e.AuthorizationURL == "" {
		e.AuthorizationURL, e.TokenURL = d.AuthorizationURL, d.TokenURL
	}
	switch d.TokenAuth {
	case providers.AuthBasic:
		e.TokenAuthMethod = authBasic
	case providers.AuthQuery:
		e.TokenAuthMethod = providers.AuthQuery
	}
	if cfg.Social != nil && cfg.Social.BaseURL != "" {
		e.UserInfoURL = strings.Replace(e.UserInfoURL, providers.BaseURLPlaceholder, cfg.Social.BaseURL, 1)
	}
	if d.PKCE == providers.PKCES256 {
		e.PKCEMethod = "S256"
	}
	return e
}

// socialProvider runs one descriptor: the authorization-code flow, one token
// request, then the profile call(s).
type socialProvider struct {
	ps *Providers
	d  *providers.Descriptor
}

func (p socialProvider) AuthorizationURL(in StartInput) (string, error) {
	u, err := url.Parse(in.Endpoints.AuthorizationURL)
	if err != nil || in.Endpoints.AuthorizationURL == "" {
		return "", fmt.Errorf("%w: authorization endpoint", ErrInvalidConfig)
	}
	if in.State == "" || in.CallbackURL == "" || (in.Endpoints.PKCEMethod == "S256" && in.CodeChallenge == "") {
		return "", fmt.Errorf("federation: incomplete authorization request")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", in.Config.ClientID)
	q.Set(redirectParam(p.d), in.CallbackURL)
	for k, v := range p.d.AuthorizeParams {
		q.Set(k, v)
	}
	if len(in.Config.Scopes) > 0 {
		q.Set("scope", strings.Join(in.Config.Scopes, p.d.Separator()))
	}
	q.Set("state", in.State)
	if in.Endpoints.PKCEMethod == "S256" {
		q.Set("code_challenge", in.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange redeems the code once and maps the profile. No error carries a
// token, the client secret or a response body.
func (p socialProvider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	d := p.d
	if in.Endpoints.PKCEMethod != "S256" {
		in.CodeVerifier = ""
	}
	body, err := p.tokenRequest(ctx, in)
	if err != nil {
		return ProviderResult{}, err
	}
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if dec.Decode(&raw) != nil {
		return ProviderResult{}, fmt.Errorf("%w: malformed token response", ErrProviderResponse)
	}
	if d.TokenResponsePath != "" {
		obj, ok := providers.Lookup(raw, d.TokenResponsePath)
		if raw, ok = obj.(map[string]any); !ok {
			return ProviderResult{}, fmt.Errorf("%w: token response lacks %s", ErrProviderResponse, d.TokenResponsePath)
		}
		body, _ = json.Marshal(raw)
	}
	if _, has := raw["token_type"]; !has && d.TokenTypeOptional {
		raw["token_type"] = "bearer"
		body, _ = json.Marshal(raw)
	}
	tokens, err := parseTokenResponse(body, p.ps.now())
	if err != nil {
		return ProviderResult{}, err
	}
	if !strings.EqualFold(tokens.TokenType, "bearer") {
		return ProviderResult{}, fmt.Errorf("%w: token response token_type is not bearer", ErrProviderResponse)
	}
	hook := socialHooks[d.Hook]
	profileURL, err := expandTokenValues(in.Endpoints.UserInfoURL, raw)
	if err != nil {
		return ProviderResult{}, err
	}
	if hook.profileURL != nil {
		if profileURL, err = hook.profileURL(in.Endpoints, raw); err != nil {
			return ProviderResult{}, err
		}
	}
	doc, err := p.ps.socialFetch(ctx, d, d.ProfileMethod, profileURL, tokens.AccessToken, in.ClientSecret, hook)
	if err != nil {
		return ProviderResult{}, err
	}
	emailDoc := doc
	if d.EmailURL != "" {
		if emailDoc, err = p.ps.socialFetch(ctx, d, http.MethodGet, p.ps.socialURL(d.Strategy, d.EmailURL), tokens.AccessToken, in.ClientSecret, hook); err != nil {
			return ProviderResult{}, err
		}
	}
	profile, err := mapSocialProfile(d, doc, emailDoc, raw)
	if err != nil {
		return ProviderResult{}, err
	}
	if hook.after != nil {
		if err := hook.after(ctx, p.ps, d, in, tokens, &profile); err != nil {
			return ProviderResult{}, err
		}
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// socialFetch performs one bounded profile request with the access token and
// decodes a JSON object.
func (ps *Providers) socialFetch(ctx context.Context, d *providers.Descriptor, method, rawURL, token, secret string, hook socialHook) (map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil || rawURL == "" {
		return nil, fmt.Errorf("%w: bad profile URL", ErrProviderResponse)
	}
	q := req.URL.Query()
	for k, v := range d.ProfileParams {
		q.Set(k, v)
	}
	accept := "application/json"
	if d.ProfileAccept != "" {
		accept = d.ProfileAccept
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "zeroauthy")
	if name, ok := strings.CutPrefix(d.ProfileAuth, "header:"); ok {
		req.Header.Set(name, token)
	} else if name, ok := strings.CutPrefix(d.ProfileAuth, "query:"); ok {
		q.Set(name, token) // never in an error: errors carry no URL
	} else if scheme, ok := strings.CutPrefix(d.ProfileAuth, "scheme:"); ok {
		req.Header.Set("Authorization", scheme+" "+token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.URL.RawQuery = q.Encode()
	if hook.decorate != nil {
		hook.decorate(req, token, secret)
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s profile request: %w", ErrProviderResponse, d.Strategy, redact(err))
	}
	body, err := readAll(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s profile response: %w", ErrProviderResponse, d.Strategy, redact(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s profile status %d", ErrProviderResponse, d.Strategy, resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if dec.Decode(&doc) != nil || doc == nil {
		return nil, fmt.Errorf("%w: %s profile is not a JSON object", ErrProviderResponse, d.Strategy)
	}
	return doc, nil
}

// mapSocialProfile applies the descriptor's profile map. The subject is a
// string or a JSON integer, never read through float64. Optional attributes
// that are not bounded strings are dropped.
func mapSocialProfile(d *providers.Descriptor, doc, emailDoc, tokenDoc map[string]any) (Profile, error) {
	var p Profile
	lookup := func(src map[string]any, path string) (any, bool) {
		if rest, ok := strings.CutPrefix(path, providers.TokenPrefix); ok {
			return providers.Lookup(tokenDoc, rest)
		}
		return providers.Lookup(src, path)
	}
	v, ok := lookup(doc, d.Profile.UserID)
	if !ok {
		return Profile{}, fmt.Errorf("%w: %s profile lacks the user id", ErrProfile, d.Strategy)
	}
	switch id := v.(type) {
	case string:
		p.Subject = id
	case json.Number:
		if strings.ContainsAny(id.String(), ".eE-+") {
			return Profile{}, fmt.Errorf("%w: %s user id is not an integer", ErrProfile, d.Strategy)
		}
		p.Subject = id.String()
	default:
		return Profile{}, fmt.Errorf("%w: %s user id is not a string", ErrProfile, d.Strategy)
	}
	if err := ValidateSubject(p.Subject); err != nil {
		return Profile{}, err
	}
	for _, r := range p.Subject {
		if r < 0x20 || r == 0x7f {
			return Profile{}, fmt.Errorf("%w: %s user id contains control characters", ErrProfile, d.Strategy)
		}
	}
	str := func(src map[string]any, path string, limit int) *string {
		if path == "" {
			return nil
		}
		v, ok := lookup(src, path)
		if !ok {
			return nil
		}
		s, err := profileString(path, v, limit)
		if err != nil || s == "" {
			return nil
		}
		return &s
	}
	p.Name = str(doc, d.Profile.Name, 300)
	p.GivenName = str(doc, d.Profile.GivenName, 150)
	p.FamilyName = str(doc, d.Profile.FamilyName, 150)
	p.Nickname = str(doc, d.Profile.Nickname, 300)
	p.Username = str(doc, d.Profile.Username, 128)
	if pic := str(doc, d.Profile.Picture, maxSocialPictureBytes); pic != nil && strings.HasPrefix(*pic, "https://") && len(*pic) <= maxSocialPictureBytes {
		p.Picture = pic
	}
	if p.Email = str(emailDoc, d.Profile.Email, 254); p.Email != nil {
		verified := false
		switch d.EmailVerified.Rule {
		case providers.EmailAlways:
			verified = true
		case providers.EmailField:
			v, _ := lookup(emailDoc, d.EmailVerified.Path)
			verified = v == true || v == "true"
		}
		p.EmailVerified = &verified
	}
	for _, path := range d.Profile.ProviderData {
		v, ok := providers.Lookup(doc, path)
		if !ok {
			continue
		}
		switch v.(type) {
		case string, json.Number, bool:
			if p.ProviderData == nil {
				p.ProviderData = map[string]any{}
			}
			key := path
			if i := strings.LastIndex(path, "."); i >= 0 {
				key = path[i+1:]
			}
			p.ProviderData[key] = v
		}
	}
	return p, nil
}

// redirectParam is the descriptor's name for redirect_uri.
func redirectParam(d *providers.Descriptor) string {
	if d.RedirectParam != "" {
		return d.RedirectParam
	}
	return "redirect_uri"
}

// tokenRequest redeems the code once with the descriptor's request shape:
// POST (default) or GET, client credentials in the body, a basic header or
// the query, the redirect parameter's name and fixed parameters. It never
// retries; errors carry no credential, URL or body.
func (p socialProvider) tokenRequest(ctx context.Context, in ExchangeInput) ([]byte, error) {
	d := p.d
	form := url.Values{"grant_type": {"authorization_code"}, "code": {in.Code}}
	form.Set(redirectParam(d), in.CallbackURL)
	if in.CodeVerifier != "" {
		form.Set("code_verifier", in.CodeVerifier)
	}
	for k, v := range d.TokenParams {
		form.Set(k, v)
	}
	u, err := url.Parse(in.Endpoints.TokenURL)
	if err != nil || in.Endpoints.TokenURL == "" {
		return nil, fmt.Errorf("%w: token endpoint", ErrInvalidConfig)
	}
	query := u.Query()
	switch in.Endpoints.TokenAuthMethod {
	case authPost:
		form.Set("client_id", in.Config.ClientID)
		form.Set("client_secret", in.ClientSecret)
	case providers.AuthQuery:
		query.Set("client_id", in.Config.ClientID)
		query.Set("client_secret", in.ClientSecret)
	case authBasic:
	default:
		return nil, fmt.Errorf("%w: unsupported client authentication", ErrInvalidConfig)
	}
	var req *http.Request
	if d.TokenMethod == http.MethodGet {
		for k, vs := range form {
			query[k] = vs
		}
		u.RawQuery = query.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	} else {
		u.RawQuery = query.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: token endpoint", ErrInvalidConfig)
	}
	accept := "application/json"
	if d.TokenAccept != "" {
		accept = d.TokenAccept
	}
	req.Header.Set("Accept", accept)
	if in.Endpoints.TokenAuthMethod == authBasic {
		req.SetBasicAuth(url.QueryEscape(in.Config.ClientID), url.QueryEscape(in.ClientSecret))
	}
	resp, err := p.ps.client.Do(req)
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

// tokenValueRE bounds a token-response value substituted into a profile URL
// (LR39d-5).
var tokenValueRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var tokenVarRE = regexp.MustCompile(`(\{|%7B)token\.([a-z][a-z0-9_]{0,63})(\}|%7D)`)

// expandTokenValues substitutes {token.<field>} in a profile URL with the
// token response's field: a string or JSON integer matching tokenValueRE and
// not all dots, path-escaped. Anything else refuses the login before any
// profile call.
func expandTokenValues(raw string, token map[string]any) (string, error) {
	var bad error
	out := tokenVarRE.ReplaceAllStringFunc(raw, func(m string) string {
		field := tokenVarRE.FindStringSubmatch(m)[2]
		var s string
		switch v := token[field].(type) {
		case string:
			s = v
		case json.Number:
			if !strings.ContainsAny(v.String(), ".eE+-") {
				s = v.String()
			}
		}
		if !tokenValueRE.MatchString(s) || strings.Trim(s, ".") == "" {
			bad = fmt.Errorf("%w: token response %s is not a plain identifier", ErrProviderResponse, field)
			return m
		}
		return url.PathEscape(s)
	})
	if bad != nil {
		return "", bad
	}
	return out, nil
}
