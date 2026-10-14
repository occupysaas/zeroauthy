// internal/oauth/minter.go
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// GrantType is the gty claim, e.g. "client-credentials". Empty omits it.
	GrantType string
	// Lifetime defaults to DefaultAccessTokenLifetime when zero.
	Lifetime time.Duration
}

type accessTokenClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        audience `json:"aud"`
	IssuedAt        int64    `json:"iat"`
	Expiry          int64    `json:"exp"`
	Scope           string   `json:"scope,omitempty"`
	AuthorizedParty string   `json:"azp"`
	GrantType       string   `json:"gty,omitempty"`
	ID              string   `json:"jti"`
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
	iat := m.now().Unix()
	return m.Keys.Sign(ctx, p.TenantID, accessTokenClaims{
		Issuer:          p.Issuer,
		Subject:         p.Subject,
		Audience:        audience(p.Audience),
		IssuedAt:        iat,
		Expiry:          iat + int64(lifetime/time.Second),
		Scope:           strings.Join(p.Scopes, " "),
		AuthorizedParty: p.ClientID,
		GrantType:       p.GrantType,
		ID:              secrets.RandomString(24),
	})
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
	c["auth_time"] = p.AuthTime.Unix()
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
	return m.Keys.Sign(ctx, p.TenantID, c)
}
