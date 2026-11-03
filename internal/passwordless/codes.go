// Package passwordless implements email and SMS passwordless login.
package passwordless

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// NewCode returns a uniformly random decimal code of exactly length digits
// (leading zeros kept) from crypto/rand.
func NewCode(length int) string {
	out := make([]byte, length)
	ten := big.NewInt(10)
	for i := range out {
		n, err := rand.Int(rand.Reader, ten)
		if err != nil {
			panic("passwordless: entropy source failed: " + err.Error())
		}
		out[i] = byte('0' + n.Int64())
	}
	return string(out)
}

// NewLinkToken returns 32 random bytes as unpadded base64url.
func NewLinkToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("passwordless: entropy source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
