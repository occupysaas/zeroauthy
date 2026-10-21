// Package passhash parses the password hash formats Auth0's bulk user import
// accepts (password_hash and custom_password_hash) and verifies a password
// against them. A hash that verifies is later replaced by a native one, so
// nothing here is used to create hashes.
package passhash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Spec is a parsed custom_password_hash. The JSON names are Auth0's.
type Spec struct {
	Algorithm string    `json:"algorithm"`
	Hash      HashPart  `json:"hash"`
	Salt      *SaltPart `json:"salt,omitempty"`
	Password  *PassPart `json:"password,omitempty"`

	KeyLen          int `json:"keylen,omitempty"`
	Cost            int `json:"cost,omitempty"`
	BlockSize       int `json:"blockSize,omitempty"`
	Parallelization int `json:"parallelization,omitempty"`
}

// HashPart is custom_password_hash.hash.
type HashPart struct {
	Value    string   `json:"value"`
	Encoding string   `json:"encoding,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Key      *KeyPart `json:"key,omitempty"`
}

// KeyPart is the HMAC key, custom_password_hash.hash.key.
type KeyPart struct {
	Value    string `json:"value"`
	Encoding string `json:"encoding,omitempty"`
}

// SaltPart is custom_password_hash.salt.
type SaltPart struct {
	Value    string `json:"value"`
	Encoding string `json:"encoding,omitempty"`
	Position string `json:"position,omitempty"`
}

// PassPart is custom_password_hash.password.
type PassPart struct {
	Encoding string `json:"encoding,omitempty"`
}

// FieldError is a per-record import error. Code, Message and Path are the
// values Auth0 reports (docs/compat/observations/management-jobs.md, J5).
type FieldError struct {
	Code    string
	Message string
	Path    string
}

func (e FieldError) Error() string { return e.Code + " " + e.Path + ": " + e.Message }

var (
	// ErrUnusable marks an imported value that was accepted at import but
	// cannot be verified: an argon2 or pbkdf2 value that is not a valid PHC
	// string, or a value that does not decode in its declared encoding. The
	// user must reset the password (D-0044).
	ErrUnusable = errors.New("passhash: imported hash is unusable")
	// ErrNotImplemented is returned by Verify for an algorithm whose verifier
	// has not landed yet.
	ErrNotImplemented = errors.New("passhash: algorithm not implemented yet")
)

// Marshal serialises the spec for storage in an identity's imported hash.
func (s *Spec) Marshal() string {
	b, _ := json.Marshal(s) // plain strings and ints: cannot fail
	return string(b)
}

// Unmarshal reads what Marshal wrote.
func Unmarshal(v string) (*Spec, error) {
	var s Spec
	if err := json.Unmarshal([]byte(v), &s); err != nil {
		return nil, fmt.Errorf("passhash: stored spec: %w", err)
	}
	if s.Algorithm == "" {
		return nil, errors.New("passhash: stored spec has no algorithm")
	}
	return &s, nil
}

// Weak reports hashes that are cheap to brute-force: md4, md5 and sha1 without
// a salt, and the unsalted ldap {MD5} and {SHA} forms.
func (s *Spec) Weak() bool {
	switch s.Algorithm {
	case "md4", "md5", "sha1":
		return s.Salt == nil || s.Salt.Value == ""
	case "ldap":
		name, _ := ldapScheme(s.Hash.Value)
		return name == "MD5" || name == "SHA"
	}
	return false
}

const masked = "*****"

// Masked returns raw (a user record as received) with password_hash and the
// secret values of custom_password_hash replaced by "*****", as Auth0 echoes
// them. raw is not modified. Beyond Auth0's observed hash.value and salt.value
// it also masks hash.key.value, the HMAC key, which is a secret too.
func (s *Spec) Masked(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		out[k] = v
	}
	if _, ok := out["password_hash"]; ok {
		out["password_hash"] = masked
	}
	cph, ok := out["custom_password_hash"].(map[string]any)
	if !ok {
		return out
	}
	cph = maskIn(cph, "salt", "value")
	if h, ok := cph["hash"].(map[string]any); ok {
		h = maskIn(h, "", "value")
		h = maskIn(h, "key", "value")
		cph["hash"] = h
	}
	out["custom_password_hash"] = cph
	return out
}

// maskIn copies m and masks m[sub][field] (or m[field] when sub is empty).
func maskIn(m map[string]any, sub, field string) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	if sub == "" {
		if _, ok := c[field]; ok {
			c[field] = masked
		}
		return c
	}
	if inner, ok := c[sub].(map[string]any); ok {
		ic := make(map[string]any, len(inner))
		for k, v := range inner {
			ic[k] = v
		}
		if _, ok := ic[field]; ok {
			ic[field] = masked
		}
		c[sub] = ic
	}
	return c
}

func (s *Spec) passwordEncoding() string {
	if s.Password == nil || s.Password.Encoding == "" {
		return "utf8"
	}
	return s.Password.Encoding
}

// Verify checks password against the hash in constant time. It returns
// ErrUnusable for a value that cannot be parsed.
func (s *Spec) Verify(password string) (bool, error) {
	pw := encodePassword(password, s.passwordEncoding())
	switch strings.ToLower(s.Algorithm) {
	case "md4", "md5", "sha1", "sha256", "sha512":
		return s.verifyDigest(pw)
	case "hmac":
		return s.verifyHMAC(pw)
	case "ldap":
		return s.verifyLDAP(pw)
	case "bcrypt":
		return s.verifyBcrypt(pw)
	}
	return false, ErrNotImplemented
}
