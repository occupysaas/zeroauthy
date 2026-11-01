// Package eventstream provides stream configuration and delivery support.
package eventstream

import (
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errSecrets = errors.New("event stream secrets unavailable")

// SealSecrets binds write-only credentials to the tenant, stream and immutable
// destination type. The returned envelope contains no public configuration.
func SealSecrets(w keys.Wrapper, s *store.EventStream, private map[string]any) ([]byte, error) {
	if len(private) == 0 {
		return nil, nil
	}
	if s == nil || s.TenantID == "" || s.ID == "" || s.DestType == "" {
		return nil, errSecrets
	}
	plain, err := json.Marshal(private)
	if err != nil {
		return nil, errSecrets
	}
	sealed, err := keys.SealBound(w, "event-stream/v1", []string{s.TenantID, s.ID, s.DestType}, plain)
	if err != nil {
		return nil, errSecrets
	}
	return sealed, nil
}

// OpenSecrets deliberately suppresses wrapper diagnostics and ciphertext.
func OpenSecrets(w keys.Wrapper, s *store.EventStream) (map[string]any, error) {
	if s == nil {
		return nil, errSecrets
	}
	out := map[string]any{}
	if len(s.SealedSecret) == 0 {
		return out, nil
	}
	plain, err := keys.OpenBound(w, "event-stream/v1", []string{s.TenantID, s.ID, s.DestType}, s.SealedSecret)
	if err != nil {
		return nil, errSecrets
	}
	if json.Unmarshal(plain, &out) != nil || out == nil {
		return nil, errSecrets
	}
	return out, nil
}
