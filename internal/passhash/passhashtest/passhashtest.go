// Package passhashtest builds imported-hash values for tests of the sign-in
// paths that verify and upgrade them.
package passhashtest

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/passhash"
)

// BcryptPassword is the password of Bcrypt.
const BcryptPassword = "Pa55w0rd!"

// Bcrypt returns the stored form of a bcrypt import hash of BcryptPassword.
func Bcrypt() string {
	s, errs := passhash.FromBcrypt("$2b$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2")
	if len(errs) > 0 {
		panic(errs[0])
	}
	return s.Marshal()
}

// PBKDF2 returns the stored form of a PBKDF2-SHA256 import hash of password.
func PBKDF2(password string) string {
	salt := []byte("0123456789abcdef")
	key, err := pbkdf2.Key(sha256.New, password, salt, 1000, 32)
	if err != nil {
		panic(err)
	}
	b64 := base64.RawStdEncoding
	s := &passhash.Spec{Algorithm: "pbkdf2", Hash: passhash.HashPart{
		Encoding: "utf8",
		Value:    fmt.Sprintf("$pbkdf2-sha256$i=1000,l=32$%s$%s", b64.EncodeToString(salt), b64.EncodeToString(key)),
	}}
	return s.Marshal()
}

// Unusable returns the stored form of an argon2 value that is not a PHC
// string, which no password verifies against.
func Unusable() string {
	s := &passhash.Spec{Algorithm: "argon2", Hash: passhash.HashPart{Encoding: "utf8", Value: "not a phc string"}}
	return s.Marshal()
}
