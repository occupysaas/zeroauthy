// internal/oauth/minter.go
package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// DefaultAccessTokenLifetime applies when the resource server sets none.
const DefaultAccessTokenLifetime = 24 * time.Hour

type Minter struct {
	Keys *keys.Manager
	Now  func() time.Time
}

type AccessTokenParams struct {
	TenantID string
	Issuer   string
	Subject  string
	Audience []string
	ClientID string
	Scopes   []string
	// TokenDialect defaults to the legacy access_token profile.
	TokenDialect       string
	Permissions        []string
	IncludePermissions bool
	// GrantType is the gty claim, e.g. "client-credentials". Empty omits it.
	GrantType string
	// Lifetime defaults to DefaultAccessTokenLifetime when zero.
	Lifetime time.Duration
	// Operator, when not empty, is the tenant.OperatorClaim: the tenants a
	// console operator manages.
	Operator []string
	// CustomClaims contain filtered Action claims and trusted server claims
	// (including organizations); a claim the token already carries is kept.
	CustomClaims map[string]any
}

type accessTokenClaims struct {
	Issuer          string    `json:"iss"`
	Subject         string    `json:"sub"`
	Audience        audience  `json:"aud"`
	IssuedAt        int64     `json:"iat"`
	Expiry          int64     `json:"exp"`
	Scope           string    `json:"scope,omitempty"`
	AuthorizedParty string    `json:"azp,omitempty"`
	ClientID        string    `json:"client_id,omitempty"`
	Permissions     *[]string `json:"permissions,omitempty"`
	GrantType       string    `json:"gty,omitempty"`
	ID              string    `json:"jti"`
	Operator        []string  `json:"https://zeroauthy.dev/operator,omitempty"`
}

// audience encodes as a string when it has one element and as an array
// otherwise.
type audience []string

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// AccessToken returns a signed JWT access token.
func (m *Minter) AccessToken(ctx context.Context, p AccessTokenParams) (string, error) {
	if len(p.Audience) == 0 {
		return "", errors.New("oauth: an access token needs at least one audience")
	}
	lifetime := p.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultAccessTokenLifetime
	}
	dialect := p.TokenDialect
	if dialect == "" {
		dialect = "access_token"
	}
	var rfc, authz bool
	switch dialect {
	case "access_token":
	case "access_token_authz":
		authz = true
	case "rfc9068_profile":
		rfc = true
	case "rfc9068_profile_authz":
		rfc, authz = true, true
	default:
		return "", errors.New("oauth: unsupported access token dialect")
	}
	if rfc && (p.Issuer == "" || p.Subject == "" || p.ClientID == "" || slices.Contains(p.Audience, "")) {
		return "", errors.New("oauth: RFC access tokens require issuer, subject, client ID and nonempty audiences")
	}
	iat := m.now().Unix()
	c := accessTokenClaims{
		Issuer:          p.Issuer,
		Subject:         p.Subject,
		Audience:        audience(p.Audience),
		IssuedAt:        iat,
		Expiry:          iat + int64(lifetime/time.Second),
		Scope:           strings.Join(p.Scopes, " "),
		AuthorizedParty: p.ClientID,
		GrantType:       p.GrantType,
		ID:              secrets.RandomString(24),
		Operator:        p.Operator,
	}
	if authz && p.IncludePermissions {
		permissions := append([]string{}, p.Permissions...)
		slices.Sort(permissions)
		permissions = slices.Compact(permissions)
		c.Permissions = &permissions
	}
	tokenType := "JWT"
	if rfc {
		tokenType = "at+jwt"
		c.ClientID, c.AuthorizedParty, c.GrantType = p.ClientID, "", ""
	}
	if len(p.CustomClaims) == 0 {
		return m.Keys.SignWithType(ctx, p.TenantID, c, tokenType)
	}
	merged, err := withCustomClaims(c, p.CustomClaims)
	if err != nil {
		return "", err
	}
	return m.Keys.SignWithType(ctx, p.TenantID, merged, tokenType)
}

// DefaultIDTokenLifetime applies when the client sets none.
const DefaultIDTokenLifetime = 10 * time.Hour

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

type IDTokenParams struct {
	TenantID  string
	Issuer    string
	ClientID  string
	User      *store.User
	Scopes    []string
	Nonce     string
	SessionID string
	AuthTime  time.Time
	// AccessToken, when set, adds at_hash (OpenID Connect Core §3.1.3.6).
	AccessToken string
	// Lifetime defaults to DefaultIDTokenLifetime when zero.
	Lifetime time.Duration
	// CustomClaims contain filtered Action claims and trusted server claims
	// (including organizations); a claim the token already carries is kept.
	CustomClaims map[string]any
}

// IDToken returns a signed OpenID Connect ID token.
func (m *Minter) IDToken(ctx context.Context, p IDTokenParams) (string, error) {
	lifetime := p.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultIDTokenLifetime
	}
	c := claims.ForUser(p.User, p.Scopes)
	iat := m.now().Unix()
	c["iss"] = p.Issuer
	c["aud"] = p.ClientID
	c["iat"] = iat
	c["exp"] = iat + int64(lifetime/time.Second)
	if !p.AuthTime.IsZero() {
		c["auth_time"] = p.AuthTime.Unix()
	}
	if p.Nonce != "" {
		c["nonce"] = p.Nonce
	}
	if p.SessionID != "" {
		c["sid"] = p.SessionID
	}
	if p.AccessToken != "" {
		sum := sha256.Sum256([]byte(p.AccessToken))
		c["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:16])
	}
	for k, v := range p.CustomClaims {
		if _, ok := c[k]; !ok {
			c[k] = v
		}
	}
	return m.Keys.Sign(ctx, p.TenantID, c)
}

// withCustomClaims returns c's claims plus custom claims c does not carry.
func withCustomClaims(c accessTokenClaims, custom map[string]any) (map[string]any, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // iat and exp stay integers
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	for k, v := range custom {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out, nil
}
