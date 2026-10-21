package passhash

import (
	"crypto/hmac"
	"crypto/subtle"
)

// verifyHMAC computes HMAC(key, salt+password) with the declared digest; the
// salt goes where salt.position says.
func (s *Spec) verifyHMAC(pw []byte) (bool, error) {
	ctor, ok := digests[s.Hash.Digest]
	if !ok {
		return false, ErrNotImplemented // whirlpool until Task 4
	}
	if s.Hash.Key == nil {
		return false, ErrUnusable
	}
	key, err := decodeValue(s.Hash.Key.Value, s.Hash.Key.Encoding)
	if err != nil {
		return false, err
	}
	want, err := decodeValue(s.Hash.Value, s.Hash.Encoding)
	if err != nil {
		return false, err
	}
	in, err := s.saltedInput(pw)
	if err != nil {
		return false, err
	}
	m := hmac.New(ctor, key)
	m.Write(in)
	return subtle.ConstantTimeCompare(m.Sum(nil), want) == 1, nil
}
