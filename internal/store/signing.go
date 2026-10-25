package store

import "encoding/json"

// SigningKeyRotation is the detached result of one committed rotation.
type SigningKeyRotation struct {
	Current *SigningKey
	Next    *SigningKey
}

// CustomSigningKeySet stores validated public keys separately from managed keys.
type CustomSigningKeySet struct {
	TenantID string
	JWKS     json.RawMessage
}
