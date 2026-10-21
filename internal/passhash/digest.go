package passhash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

// digests maps Auth0's digest names to constructors.
var digests = map[string]func() hash.Hash{
	"md4":       md4.New,
	"md5":       md5.New,
	"sha1":      sha1.New,
	"sha224":    sha256.New224,
	"sha256":    sha256.New,
	"sha384":    sha512.New384,
	"sha512":    sha512.New,
	"ripemd160": ripemd160.New,
	"whirlpool": newWhirlpool,
}

func (s *Spec) verifyDigest(pw []byte) (bool, error) {
	want, err := decodeValue(s.Hash.Value, s.Hash.Encoding)
	if err != nil {
		return false, err
	}
	in, err := s.saltedInput(pw)
	if err != nil {
		return false, err
	}
	ctor, ok := digests[s.Algorithm]
	if !ok {
		return false, fmt.Errorf("%w: digest %q", ErrUnusable, s.Algorithm)
	}
	h := ctor()
	h.Write(in)
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1, nil
}
