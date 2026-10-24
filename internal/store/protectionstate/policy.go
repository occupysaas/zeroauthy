package protectionstate

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
)

func (s *State) Policy(old, next store.ProtectionSettings) {
	for id, b := range s.Buckets {
		clear := false
		switch b.Limit.Key.Kind {
		case store.ProtectionBruteForce:
			clear = old.BruteForce.Mode != next.BruteForce.Mode || old.LegacyLockoutSeconds != next.LegacyLockoutSeconds || next.BruteForce.MaxAttempts > old.BruteForce.MaxAttempts
			if !clear && next.BruteForce.MaxAttempts > 0 && next.BruteForce.MaxAttempts < old.BruteForce.MaxAttempts {
				b.Limit.Capacity = next.BruteForce.MaxAttempts
			}
		case store.ProtectionSuspiciousIPLogin:
			clear = old.SuspiciousIP.Stage.PreLogin != next.SuspiciousIP.Stage.PreLogin || old.LegacyIPMaxAttempts != next.LegacyIPMaxAttempts || old.LegacyLockoutSeconds != next.LegacyLockoutSeconds
		case store.ProtectionSuspiciousIPRegistration:
			clear = old.SuspiciousIP.Stage.PreUserRegistration != next.SuspiciousIP.Stage.PreUserRegistration
		}
		if clear {
			delete(s.Buckets, id)
		}
	}
}

// UserFilters covers normalized aliases only in the user's own identity connections.
func UserFilters(u *store.User, connections []*store.Connection) []store.ProtectionFilter {
	var fs []store.ProtectionFilter
	for _, c := range connections {
		for i := range u.Identities {
			identity := &u.Identities[i]
			if identity.Connection != c.Name {
				continue
			}
			email, username := u.IdentityLogin(identity)
			aliases := []string{email, username}
			if email == "" && username == "" {
				aliases = append(aliases, identity.UserID)
			}
			for _, alias := range aliases {
				if alias != "" {
					fs = append(fs, store.ProtectionFilter{ConnectionID: c.ID, Identifier: strings.ToLower(strings.TrimSpace(alias))})
				}
			}
		}
	}
	return fs
}
