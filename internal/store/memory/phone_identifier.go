package memory

import (
	"github.com/zeroauthy/zeroauthy/internal/phonenumber"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// checkPhone runs under the same store lock as the eventual write. Old
// unchecked values are normalized only for comparison, never rewritten.
func (r users) checkPhone(u *store.User) error {
	n, err := phonenumber.NormalizeE164(u.PhoneNumber, "")
	u.PhoneNormalized = n
	for _, id := range u.Identities {
		var c *store.Connection
		for _, candidate := range r.s.connections {
			if candidate.TenantID == u.TenantID && candidate.Name == id.Connection {
				c = candidate
				break
			}
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
		for _, other := range r.s.users {
			if other.TenantID != u.TenantID || other.UserID == u.UserID {
				continue
			}
			on, _ := phonenumber.NormalizeE164(other.PhoneNumber, "")
			if on != n {
				continue
			}
			for _, oi := range other.Identities {
				if oi.Connection == id.Connection {
					return store.ErrConflict
				}
			}
		}
	}
	return nil
}
