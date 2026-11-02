package mfa

import (
	"encoding/base32"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SealTOTPSecret seals enrollment or imported TOTP material under the master
// key, bound to its tenant, user and authenticator. Errors never include material.
func SealTOTPSecret(w keys.Wrapper, tid, uid, id, secret string) ([]byte, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 || tid == "" || uid == "" || id == "" {
		return nil, store.ErrInvalid
	}
	if w == nil {
		return nil, errSealing
	}
	sealed, err := w.Wrap([]byte(secret), totpAAD(tid, uid, id))
	if err != nil {
		return nil, errSealing
	}
	return sealed, nil
}
