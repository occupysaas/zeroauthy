package store

import "time"

// ClientCredential is a public key or certificate registered on a client for
// private_key_jwt authentication or signed request objects.
type ClientCredential struct {
	TenantID, ClientID, ID, Type, Name, KID, Alg string // Type: "public_key" | "x509_cert"
	PublicKeyDER                                 []byte // PKIX SubjectPublicKeyInfo
	Thumbprint                                   string // base64url SHA-256 of the RFC 7638 JWK thumbprint input (thumbprint_sha256)
	ExpiresAt                                    *time.Time
	CreatedAt, UpdatedAt                         time.Time
}
