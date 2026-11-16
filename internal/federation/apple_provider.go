package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// AppleEndpoints returns Apple's fixed production endpoints.
func AppleEndpoints() Endpoints {
	return Endpoints{AuthorizationURL: rules.AppleAuthorizationURL, TokenURL: rules.AppleTokenURL, JWKSURL: rules.AppleJWKSURL, TokenAuthMethod: authPost}
}

// AppleOverride is a construction-only fixture hook; connection options never
// control Apple's endpoints or issuer.
type AppleOverride struct {
	Endpoints            Endpoints
	Issuer, DiscoveryURL string
}

func (ps *Providers) WithAppleFixture(o AppleOverride) *Providers { ps.appleFix = &o; return ps }
func (ps *Providers) apple() AppleOverride {
	if ps.appleFix != nil {
		return *ps.appleFix
	}
	return AppleOverride{Endpoints: AppleEndpoints(), Issuer: rules.AppleIssuer, DiscoveryURL: rules.AppleDiscoveryURL}
}

// AppleMetadata pins fixed endpoints and only uses discovery to determine
// advertised S256 support. Unlike generic OIDC, omission means omit PKCE.
func (ps *Providers) AppleMetadata(ctx context.Context, key CacheKey) (Metadata, error) {
	a := ps.apple()
	ck := key.with("apple-metadata", a.DiscoveryURL, a.Issuer)
	if m, ok := ps.discovery.get(ck); ok {
		return m, nil
	}
	var raw map[string]any
	if err := ps.getJSON(ctx, a.DiscoveryURL, "", &raw); err != nil {
		return Metadata{}, err
	}
	bad := func() (Metadata, error) {
		return Metadata{}, fmt.Errorf("%w: invalid Apple metadata", ErrProviderResponse)
	}
	if issuer, ok := raw["issuer"].(string); !ok || issuer != a.Issuer {
		return bad()
	}
	s256 := false
	if v, present := raw["code_challenge_methods_supported"]; present {
		list, ok := v.([]any)
		if !ok {
			return bad()
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return bad()
			}
			s256 = s256 || s == "S256"
		}
	}
	m := Metadata{Issuer: a.Issuer, AuthorizationEndpoint: a.Endpoints.AuthorizationURL, TokenEndpoint: a.Endpoints.TokenURL, JWKSURI: a.Endpoints.JWKSURL, TokenAuthMethod: authPost, PKCES256: s256}
	ps.discovery.put(ck, m)
	return m, nil
}

type appleProvider struct{ ps *Providers }

func (p appleProvider) AuthorizationURL(in StartInput) (string, error) {
	if in.State == "" || in.CallbackURL == "" || in.Nonce == "" || (in.Endpoints.PKCES256 && in.CodeChallenge == "") {
		return "", fmt.Errorf("%w: incomplete Apple authorization request", ErrInvalidConfig)
	}
	u, err := url.Parse(p.ps.apple().Endpoints.AuthorizationURL)
	if err != nil {
		return "", ErrInvalidConfig
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", in.Config.ClientID)
	q.Set("redirect_uri", in.CallbackURL)
	q.Set("state", in.State)
	q.Set("nonce", in.Nonce)
	q.Set("response_mode", "query")
	if slices.Contains(in.Config.Scopes, "name") || slices.Contains(in.Config.Scopes, "email") {
		q.Set("response_mode", "form_post")
	}
	if len(in.Config.Scopes) > 0 {
		q.Set("scope", strings.Join(in.Config.Scopes, " "))
	}
	if in.Endpoints.PKCES256 {
		q.Set("code_challenge", in.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (p appleProvider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	if in.Config.Strategy != StrategyApple {
		return ProviderResult{}, ErrInvalidConfig
	}
	key, err := rules.ParseAppleSigningKey(in.ClientSecret)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: invalid Apple signing key", ErrInvalidConfig)
	}
	secret, err := p.ps.appleClientSecret(in.Cache, in.Config.AppleTeamID, in.Config.AppleKID, in.Config.ClientID, key)
	if err != nil {
		return ProviderResult{}, err
	}
	a := p.ps.apple()
	in.Issuer = a.Issuer
	in.ClientSecret = secret
	if !in.Endpoints.PKCES256 {
		in.CodeVerifier = ""
	}
	tokens, err := p.ps.exchangeCode(ctx, a.Endpoints.TokenURL, authPost, in)
	if err != nil {
		return ProviderResult{}, err
	}
	claims, err := p.ps.validateIDToken(ctx, in, a.Endpoints, tokens)
	if err != nil {
		return ProviderResult{}, err
	}
	profile, err := appleProfile(claims, in.AppleUser)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("%w: invalid Apple profile", ErrProviderResponse)
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// AppleUser carries only first-authorization names. Email always comes from
// the verified ID token. Web callers must bind this to a name-requesting attempt.
type AppleUser struct{ FirstName, LastName string }

// ParseAppleUser bounds both the browser user and native user_profile JSON.
func ParseAppleUser(raw string) (*AppleUser, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 1024 || !utf8.ValidString(raw) {
		return nil, ErrProfile
	}
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, ErrProfile
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, ErrProfile
	}
	u := &AppleUser{}
	if n, ok := m["name"]; ok {
		var name map[string]any
		if json.Unmarshal(n, &name) != nil || name == nil {
			return nil, ErrProfile
		}
		for _, f := range []struct {
			k   string
			dst *string
		}{{"firstName", &u.FirstName}, {"lastName", &u.LastName}} {
			if v, ok := name[f.k]; ok {
				s, err := profileString(f.k, v, 150)
				if err != nil {
					return nil, err
				}
				*f.dst = s
			}
		}
	}
	if err := validateAppleUser(u); err != nil {
		return nil, err
	}
	return u, nil
}
func appleProfile(c map[string]any, user *AppleUser) (Profile, error) {
	sub, _ := c["sub"].(string)
	p, err := profileFromClaims(sub, c)
	if err != nil {
		return Profile{}, err
	}
	verified := c["email_verified"] == true || c["email_verified"] == "true"
	p.EmailVerified = &verified
	for _, k := range []string{"is_private_email", "real_user_status"} {
		if v, ok := c[k]; ok {
			valid := false
			switch k {
			case "is_private_email":
				switch v.(type) {
				case bool:
					valid = true
				case string:
					valid = v == "true" || v == "false"
				}
			case "real_user_status":
				if n, ok := v.(json.Number); ok {
					i, err := n.Int64()
					valid = err == nil && i >= 0 && i <= 2
					v = float64(i)
				}
			}
			if valid {
				if p.ProviderData == nil {
					p.ProviderData = map[string]any{}
				}
				p.ProviderData[k] = v
			}
		}
	}
	if user != nil {
		if err := validateAppleUser(user); err != nil {
			return Profile{}, err
		}
		if p.GivenName == nil && user.FirstName != "" {
			p.GivenName = &user.FirstName
		}
		if p.FamilyName == nil && user.LastName != "" {
			p.FamilyName = &user.LastName
		}
		if p.Name == nil {
			name := strings.TrimSpace(user.FirstName + " " + user.LastName)
			if name != "" {
				p.Name = &name
			}
		}
	}
	if p.Nickname == nil {
		nick := sub
		if p.Email != nil && *p.Email != "" {
			nick, _, _ = strings.Cut(*p.Email, "@")
		} else {
			r := []rune(nick)
			if len(r) > 20 {
				nick = string(r[:20])
			}
		}
		p.Nickname = &nick
	}
	return p, nil
}

func validateAppleUser(u *AppleUser) error {
	for _, f := range []struct {
		key, value string
		limit      int
	}{{"firstName", u.FirstName, 150}, {"lastName", u.LastName, 150}, {"name", strings.TrimSpace(u.FirstName + " " + u.LastName), 300}} {
		if !utf8.ValidString(f.value) {
			return ErrProfile
		}
		if _, err := profileString(f.key, f.value, f.limit); err != nil {
			return err
		}
	}
	return nil
}
