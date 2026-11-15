package keys

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
