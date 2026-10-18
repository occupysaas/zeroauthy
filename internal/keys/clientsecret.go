package keys

import "errors"

// clientSecretAAD binds a sealed secret to its tenant and client, so a blob
// copied between clients or tenants does not open. The prefix keeps it
// distinct from other sealed values for the same IDs.
func clientSecretAAD(tenantID, clientID string) []byte {
	return []byte("client-secret|" + tenantID + "|" + clientID)
}

// SealClientSecret envelope-encrypts a client secret under the master key
// (D-0038). Errors never include the secret.
func SealClientSecret(w Wrapper, tenantID, clientID, secret string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("keys: a master key wrapper is required to seal a client secret")
	}
	if secret == "" {
		return nil, errors.New("keys: empty client secret")
	}
	return seal(w, []byte(secret), clientSecretAAD(tenantID, clientID))
}

// OpenClientSecret reverses SealClientSecret. It fails on a missing wrapper,
// an empty blob, a wrong key or a blob sealed for another client.
func OpenClientSecret(w Wrapper, tenantID, clientID string, sealed []byte) (string, error) {
	if w == nil {
		return "", errors.New("keys: a master key wrapper is required to open a client secret")
	}
	if len(sealed) == 0 {
		return "", errors.New("keys: empty sealed client secret")
	}
	plain, err := unseal(w, sealed, clientSecretAAD(tenantID, clientID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
