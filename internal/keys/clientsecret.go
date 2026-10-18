package keys

import (
	"encoding/binary"
	"errors"
)

// clientSecretAAD binds a sealed secret to its tenant and client, so a blob
// copied between clients or tenants does not open. Client IDs come from
// seeds and API callers and may contain any character, so a separator alone
// would be ambiguous ("a|b"+"c" vs "a"+"b|c"): each field is length-prefixed,
// which makes the encoding injective. The label keeps it distinct from other
// sealed values for the same IDs.
func clientSecretAAD(tenantID, clientID string) []byte {
	return lengthPrefixed("client-secret/v1", tenantID, clientID)
}

// lengthPrefixed encodes each field as a 4-byte big-endian length followed
// by its bytes.
func lengthPrefixed(fields ...string) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
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
