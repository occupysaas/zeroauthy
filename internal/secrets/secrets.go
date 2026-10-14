// Package secrets hashes credentials with argon2id and generates random
// identifiers.
package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters follow the OWASP minimum recommendation for argon2id.
const (
	memoryKiB = 19456
	timeCost  = 2
	threads   = 1
	saltLen   = 16
	keyLen    = 32
)

// Bounds for parameters read from stored hashes. They keep a corrupt or
// hostile stored value from panicking argon2 or exhausting memory.
const (
	maxMemoryKiB = 256 * 1024 // 256 MiB
	maxTimeCost  = 10
	minSaltLen   = 8
	maxSaltLen   = 64
	minKeyLen    = 16
	maxKeyLen    = 64
)

var errMalformed = errors.New("secrets: malformed argon2id hash")

// Hash returns an argon2id PHC string for secret.
func Hash(secret string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(secret), salt, timeCost, memoryKiB, threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, timeCost, threads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// Verify reports whether secret matches the PHC string encoded. It uses the
// parameters stored in encoded, so hashes made with older parameters still
// verify.
func Verify(encoded, secret string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errMalformed
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errMalformed
	}
	if t < 1 || t > maxTimeCost || p < 1 || m < 8*uint32(p) || m > maxMemoryKiB {
		return false, errMalformed
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return false, errMalformed
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < minKeyLen || len(want) > maxKeyLen {
		return false, errMalformed
	}
	got := argon2.IDKey([]byte(secret), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// HashToken returns the hex SHA-256 of a high-entropy token (session
// cookie, authorization code, transaction cookie). Such tokens are stored
// only in this form. Never use it for passwords; use Hash.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// RandomHex returns nBytes of crypto/rand output as lowercase hex. It panics
// if the system random source fails.
func RandomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("secrets: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// RandomString returns n characters drawn uniformly from [A-Za-z0-9] using
// crypto/rand. It panics if the system random source fails.
func RandomString(n int) string {
	const limit = 256 - 256%len(alphabet) // reject bytes that would bias the result
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("secrets: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}
