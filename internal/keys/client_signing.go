package keys

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

// ClientSigningSecret opens the newest usable confidential-client secret.
// Hash-only legacy secrets cannot be used as symmetric signing keys.
func ClientSigningSecret(w Wrapper, c *store.Client, now time.Time) ([]byte, error) {
	invalid := errors.New("keys: no usable client ID-token signing secret")
	if c == nil || c.AppType == store.AppTypeSPA || c.AppType == store.AppTypeNative || (c.TokenEndpointAuthMethod != store.AuthMethodClientSecretPost && c.TokenEndpointAuthMethod != store.AuthMethodClientSecretBasic) {
		return nil, invalid
	}
	var current *store.ClientSecret
	for i := range c.Secrets {
		secret := &c.Secrets[i]
		if len(secret.Sealed) == 0 || secret.ExpiresAt != nil && !now.Before(*secret.ExpiresAt) {
			continue
		}
		if current == nil || secret.CreatedAt.After(current.CreatedAt) {
			current = secret
		}
	}
	if current == nil {
		return nil, invalid
	}
	plain, err := OpenClientSecret(w, c.TenantID, c.ClientID, current.Sealed)
	if err != nil || len(plain) < 32 {
		return nil, invalid
	}
	return []byte(plain), nil
}
