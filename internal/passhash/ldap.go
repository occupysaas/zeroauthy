package passhash

import (
	"crypto/subtle"
	"hash"
	"strings"
)

type ldapKind struct {
	ctor   func() hash.Hash
	salted bool
}

// ldapKinds are the RFC 2307 schemes Auth0 accepts. {CRYPT} and {CLEARTEXT}
// are refused at parse.
var ldapKinds = map[string]ldapKind{
	"MD5":     {digests["md5"], false},
	"SMD5":    {digests["md5"], true},
	"SHA":     {digests["sha1"], false},
	"SSHA":    {digests["sha1"], true},
	"SHA256":  {digests["sha256"], false},
	"SSHA256": {digests["sha256"], true},
	"SHA384":  {digests["sha384"], false},
	"SSHA384": {digests["sha384"], true},
	"SHA512":  {digests["sha512"], false},
	"SSHA512": {digests["sha512"], true},
}

// ldapScheme splits "{scheme}body" into the upper-cased scheme and the body.
// Schemes are case-insensitive (RFC 2307). ok is false when v has no scheme.
func ldapScheme(v string) (name, body string) {
	if !strings.HasPrefix(v, "{") {
		return "", ""
	}
	end := strings.IndexByte(v, '}')
	if end < 0 {
		return "", ""
	}
	return strings.ToUpper(v[1:end]), v[end+1:]
}

func (s *Spec) verifyLDAP(pw []byte) (bool, error) {
	name, body := ldapScheme(s.Hash.Value)
	kind, ok := ldapKinds[name]
	if !ok {
		return false, ErrUnusable
	}
	raw := decodeBase64(body)
	h := kind.ctor()
	sum, salt := raw, []byte(nil)
	if kind.salted {
		if len(raw) < h.Size() {
			return false, ErrUnusable
		}
		sum, salt = raw[:h.Size()], raw[h.Size():]
	}
	h.Write(pw)
	h.Write(salt)
	return subtle.ConstantTimeCompare(h.Sum(nil), sum) == 1, nil
}
