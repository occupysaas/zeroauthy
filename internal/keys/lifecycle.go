package keys

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// VerificationKeys returns only managed current, next and previous keys.
// Custom public JWKS are intentionally not an authentication trust source.
func (m *Manager) VerificationKeys(ctx context.Context, tenantID string) (jose.JSONWebKeySet, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext, store.KeyPrevious} {
		for _, k := range ks {
			if k.Status != status {
				continue
			}
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
				return jose.JSONWebKeySet{}, fmt.Errorf("keys: stored JWK %s: %w", k.KID, err)
			}
			set.Keys = append(set.Keys, jwk)
		}
	}
	return set, nil
}
