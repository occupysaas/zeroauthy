package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// RFC 7636 §4.1: 43-128 characters from the unreserved set.
var codeVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// verifyPKCE checks a code_verifier against the stored challenge. Only
// S256 is supported.
func verifyPKCE(method, challenge, verifier string) bool {
	if method != "S256" || !codeVerifierPattern.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
