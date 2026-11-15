// internal/oauth/minter.go
package oauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	// SigningAlg is the API's signing_alg: RS256 (also when empty), HS256 or
	// PS256. SigningSecret is the opened HS256 secret, required for HS256 and
	// ignored otherwise.
	SigningAlg    string
	SigningSecret []byte
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
	alg := p.SigningAlg
	switch alg {
	case "", "RS256", "PS256":
	case "HS256":
		if len(p.SigningSecret) == 0 {
			return "", errors.New("oauth: an HS256 access token needs the API's signing secret")
		}
	default:
		return "", errors.New("oauth: unsupported access token signing algorithm")
	}
	if alg == "HS256" {
		// The tenant cannot verify a secret-signed token, so /userinfo is not
		// an audience of one (LR35-9).
		p.Audience = slices.DeleteFunc(slices.Clone(p.Audience), func(a string) bool { return a == p.Issuer+"userinfo" })
	}
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
	var payload any = c
	if len(p.CustomClaims) > 0 {
		merged, err := withCustomClaims(c, p.CustomClaims)
		if err != nil {
			return "", err
		}
		payload = merged
	}
	if alg == "HS256" {
		return signHS256(payload, p.SigningSecret, tokenType)
	}
	if alg == "" {
		alg = "RS256"
	}
	return m.Keys.SignWithAlg(ctx, p.TenantID, payload, tokenType, jose.SignatureAlgorithm(alg))
}

// signHS256 signs claims with the API's secret. The header carries no kid:
// the secret is not a published key. go-jose refuses secrets under 32 bytes
// (RFC 7518 3.2), but the API accepts 16 characters and up (C15), so the
// compact JWS is built here.
func signHS256(claims any, secret []byte, tokenType string) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{"HS256", tokenType})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil)), nil
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
	MFAAt     time.Time
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
	if !p.MFAAt.IsZero() {
		c["amr"] = []string{"mfa"}
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
