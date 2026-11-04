package passhash

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// bcryptMaxInput is bcrypt's input limit. Auth0's bcrypt cuts longer input
// (salt included) where x/crypto/bcrypt refuses it.
const bcryptMaxInput = 72

func (s *Spec) verifyBcrypt(pw []byte) (bool, error) {
	in, err := s.saltedInput(pw)
	if err != nil {
		return false, err
	}
	if len(in) > bcryptMaxInput {
		in = in[:bcryptMaxInput]
	}
	// An over-cap cost is refused, not run: it would hold the login for
	// hours. ParseCustom rejects it; this guards a stored value.
	if c, err := bcrypt.Cost([]byte(s.Hash.Value)); err != nil || c > maxBcryptCost {
		return false, ErrUnusable
	}
	switch err := bcrypt.CompareHashAndPassword([]byte(s.Hash.Value), in); {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, nil
	default:
		return false, ErrUnusable
	}
}
