// Package logstream holds stream configuration secrets and delivery support.
package logstream

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errSecrets = errors.New("log stream secrets unavailable")

// SealSecrets binds only the private sink fields to this tenant, stream and
// immutable sink type. Public fields remain in LogStream.Sink.
func SealSecrets(w keys.Wrapper, s *store.LogStream, private map[string]any) ([]byte, error) {
	if len(private) == 0 {
		return nil, nil
	}
	if s == nil || s.TenantID == "" || s.ID == "" || s.Type == "" {
		return nil, errSecrets
	}
	plain, err := json.Marshal(private)
	if err != nil {
		return nil, errSecrets
	}
	sealed, err := keys.SealBound(w, "log-stream/v1", []string{s.TenantID, s.ID, s.Type}, plain)
	if err != nil {
		return nil, errSecrets
	}
	return sealed, nil
}

// OpenSecrets is shared by Management updates and the delivery worker. Errors
// deliberately omit the ciphertext, credentials and wrapper diagnostics.
func OpenSecrets(w keys.Wrapper, s *store.LogStream) (map[string]any, error) {
	if s == nil {
		return nil, errSecrets
	}
	out := map[string]any{}
	if len(s.SealedSecrets) == 0 {
		return out, nil
	}
	plain, err := keys.OpenBound(w, "log-stream/v1", []string{s.TenantID, s.ID, s.Type}, s.SealedSecrets)
	if err != nil {
		return nil, errSecrets
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.UseNumber()
	if decoder.Decode(&out) != nil || out == nil {
		return nil, errSecrets
	}
	return out, nil
}
