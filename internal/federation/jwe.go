package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
	"strings"
)

// oaepExtendedKey uses the standard library for the SHA-384/SHA-512 OAEP
// key-management variants; go-jose handles content authentication/decryption.
type oaepExtendedKey struct {
	key *rsa.PrivateKey
	alg string
}

func (k oaepExtendedKey) DecryptKey(encrypted []byte, h jose.Header) ([]byte, error) {
	if h.Algorithm != k.alg {
		return nil, fmt.Errorf("key algorithm mismatch")
	}
	hash := sha512.New384()
	if k.alg == "RSA-OAEP-512" {
		hash = sha512.New()
	}
	return rsa.DecryptOAEP(hash, rand.Reader, k.key, encrypted, nil)
}
func decryptIDToken(raw string, keys []*store.ConnectionKey, open func(*store.ConnectionKey) (crypto.Signer, error), alg string, encs []string) (string, error) {
	bad := func() (string, error) { return "", idTokenError("encrypted token refused") }
	if len(raw) > maxTokenBytes || strings.Count(raw, ".") != 4 || !slices.Contains(rules.EncryptionAlgorithms, alg) {
		return bad()
	}
	parts := strings.Split(raw, ".")
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return bad()
	}
	var protected map[string]json.RawMessage
	if json.Unmarshal(b, &protected) != nil {
		return bad()
	}
	if _, ok := protected["zip"]; ok {
		return bad()
	}
	allowed := encs
	if len(allowed) == 0 {
		allowed = rules.ContentAlgorithms
	}
	content := []jose.ContentEncryption{}
	for _, v := range allowed {
		if !slices.Contains(rules.ContentAlgorithms, v) {
			return bad()
		}
		content = append(content, jose.ContentEncryption(v))
	}
	obj, e := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.KeyAlgorithm(alg)}, content)
	if e != nil {
		return bad()
	}
	for _, k := range keys {
		if k.Use != "encryption" || (k.State != "current" && k.State != "previous") || (obj.Header.KeyID != "" && k.KID != obj.Header.KeyID) {
			continue
		}
		key, e := open(k)
		if e != nil {
			continue
		}
		var decryptKey any = key
		if alg == "RSA-OAEP-384" || alg == "RSA-OAEP-512" {
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				continue
			}
			decryptKey = oaepExtendedKey{rsaKey, alg}
		}
		plain, e := obj.Decrypt(decryptKey)
		if e == nil && len(plain) <= maxTokenBytes {
			return string(plain), nil
		}
	}
	return bad()
}
