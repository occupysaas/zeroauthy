package keys

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// envelope is the stored form of an encrypted private key. A random data
// encryption key (DEK) encrypts the payload, and the Wrapper encrypts the
// DEK. Both layers are bound to the same AAD.
type envelope struct {
	Version int    `json:"v"`
	DEK     []byte `json:"dek"` // wrapped DEK
	CT      []byte `json:"ct"`  // nonce || AES-256-GCM ciphertext under the DEK
}

func seal(w Wrapper, plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	ct, err := gcmSeal(aead, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := w.Wrap(dek, aad)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Version: 1, DEK: wrapped, CT: ct})
}

func unseal(w Wrapper, blob, aad []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("keys: malformed envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("keys: unsupported envelope version %d", env.Version)
	}
	dek, err := w.Unwrap(env.DEK, aad)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return gcmOpen(aead, env.CT, aad)
}
