package passhash

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// verifyScrypt derives keylen bytes with scrypt(password, salt, N=cost,
// r=blockSize, p=parallelization) and compares them with the hash. The salt is
// a plain KDF salt (its position has no meaning here).
func (s *Spec) verifyScrypt(pw []byte) (bool, error) {
	if s.KeyLen < 1 || s.KeyLen > maxKDFKeyLen || s.Cost < 2 || s.BlockSize < 1 || s.Parallelization < 1 ||
		scryptMemory(uint64(s.Cost), uint64(s.BlockSize), uint64(s.Parallelization)) > maxKDFMemory ||
		scryptWork(uint64(s.Cost), uint64(s.BlockSize), uint64(s.Parallelization)) > maxScryptWork {
		return false, fmt.Errorf("%w: scrypt parameters", ErrUnusable)
	}
	want, err := decodeValue(s.Hash.Value, s.Hash.Encoding)
	if err != nil {
		return false, err
	}
	var salt []byte
	if s.Salt != nil {
		if salt, err = decodeValue(s.Salt.Value, s.Salt.Encoding); err != nil {
			return false, err
		}
	}
	got, err := scrypt.Key(pw, salt, s.Cost, s.BlockSize, s.Parallelization, s.KeyLen)
	if err != nil {
		return false, fmt.Errorf("%w: scrypt: %v", ErrUnusable, err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
