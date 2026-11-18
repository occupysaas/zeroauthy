package keys

import (
	"crypto/rand"
	"encoding/base64"
)

// GeneratedAPISigningSecretBytes is the size of a generated HS256 secret:
// 32 random bytes, 43 base64url characters.
const GeneratedAPISigningSecretBytes = 32

// NewAPISigningSecret returns a random HS256 signing secret.
func NewAPISigningSecret() (string, error) {
	raw := make([]byte, GeneratedAPISigningSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// apiSigningSecretLabel names the format of a sealed HS256 API signing
// secret, apart from every other sealed domain.
const apiSigningSecretLabel = "api-signing-secret/v1"

// SealAPISigningSecret seals an API's HS256 signing secret under the master
// key, bound to its tenant and resource server. Errors never include the
// secret.
func SealAPISigningSecret(w Wrapper, tenantID, resourceServerID, secret string) ([]byte, error) {
	return SealBound(w, apiSigningSecretLabel, []string{tenantID, resourceServerID}, []byte(secret))
}

// OpenAPISigningSecret reverses SealAPISigningSecret. It fails for a secret
// sealed for another tenant or resource server.
func OpenAPISigningSecret(w Wrapper, tenantID, resourceServerID string, sealed []byte) ([]byte, error) {
	return OpenBound(w, apiSigningSecretLabel, []string{tenantID, resourceServerID}, sealed)
}
