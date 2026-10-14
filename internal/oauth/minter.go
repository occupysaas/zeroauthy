// internal/oauth/minter.go
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
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
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	iat := now().Unix()
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
