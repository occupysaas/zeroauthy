// Package keys manages per-tenant token signing keys: generation, envelope
// encryption at rest, rotation, JWKS publication and signing.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Wrapper encrypts data keys under a key-encryption key. LocalWrapper uses
// a configured master key; a KMS-backed implementation can replace it.
type Wrapper interface {
	Wrap(plaintext, aad []byte) ([]byte, error)
	Unwrap(ciphertext, aad []byte) ([]byte, error)
}

// LocalWrapper is AES-256-GCM under a 32-byte master key. Output is
// nonce || ciphertext.
type LocalWrapper struct{ aead cipher.AEAD }

func NewLocalWrapper(masterKey []byte) (*LocalWrapper, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("keys: master key must be 32 bytes, got %d", len(masterKey))
	}
	aead, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}
	return &LocalWrapper{aead: aead}, nil
}

func (w *LocalWrapper) Wrap(plaintext, aad []byte) ([]byte, error) {
	return gcmSeal(w.aead, plaintext, aad)
}

func (w *LocalWrapper) Unwrap(ciphertext, aad []byte) ([]byte, error) {
	return gcmOpen(w.aead, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func gcmSeal(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(aead cipher.AEAD, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("keys: ciphertext too short")
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("keys: decryption failed")
	}
	return pt, nil
}
