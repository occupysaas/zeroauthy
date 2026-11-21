package store

import (
	"context"
	"strings"
	"time"
)

// GlobalRevocationStore is part of oidc_logout.v1. Replay consumption must be
// in the same transaction as revocation. Email candidates are restricted to
// owners in the selected connection's federated identity index.
type GlobalRevocationStore interface {
	UseGlobalRevocationJTI(context.Context, string, string, string, time.Time, time.Time) error
	PurgeGlobalRevocationJTIs(context.Context, time.Time, int) (int, error)
	FindByFederatedEmail(context.Context, string, string, string) (*User, error)
}

func FederatedEmailMatches(u *User, connection, email string) bool {
	if u == nil || email == "" {
		return false
	}
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Connection != connection || !IsFederatedProvider(id.Provider) {
			continue
		}
		candidate, _ := u.IdentityLogin(id)
		if strings.EqualFold(candidate, email) {
			return true
		}
	}
	return false
}
