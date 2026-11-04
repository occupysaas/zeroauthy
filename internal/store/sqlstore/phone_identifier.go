package sqlstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/phonenumber"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (r users) checkPhone(ctx context.Context, u *store.User) error {
	n, err := phonenumber.NormalizeE164(u.PhoneNumber, "")
	u.PhoneNormalized = n
	for _, id := range u.Identities {
		c, e := r.s.Connections().GetByName(ctx, u.TenantID, id.Connection)
		if e == store.ErrNotFound {
			continue
		}
		if e != nil {
			return e
		}
		if !store.PhoneIdentifierActive(c) {
			continue
		}
		if u.PhoneNumber == "" {
			continue
		}
		if err != nil {
			return store.ErrInvalid
		}
		u.PhoneNumber = n
		matches, e := r.s.Phone().FindUsersByPhone(ctx, u.TenantID, id.Connection, n)
		if e != nil {
			return e
		}
		for _, other := range matches {
			if other.UserID != u.UserID {
				return store.ErrConflict
			}
		}
	}
	return nil
}
