package federation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	// ErrUserBlocked: the identity's owner is blocked locally.
	ErrUserBlocked = errors.New("federation: user is blocked")
	// ErrIdentityConflict: the identity's local public ID is taken by a user
	// that does not own it (another connection of the same provider, say).
	// Nothing is merged.
	ErrIdentityConflict = errors.New("federation: identity conflicts with an existing user")
)

// Service coordinates federated login. ResolveIdentity is its transactional
// identity half; Start and Complete (Task 9) drive the browser flow.
type Service struct {
	Wrapper keys.Wrapper
	Now     func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ResolveIdentity runs inside the caller's transaction tx. It finds the
// identity's owner through the identity index (never by email), provisions a
// user on first login, synchronizes provider-owned profile fields under the
// connection's policy, and replaces the sealed token record. It creates no
// session. A concurrent first login returns store.ErrConflict; the caller may
// retry its transaction once.
func (s *Service) ResolveIdentity(ctx context.Context, tx store.Store, conn *store.Connection, res ProviderResult) (*store.User, error) {
	p := res.Profile
	if err := ValidateSubject(p.Subject); err != nil {
		return nil, err
	}
	key := store.FederatedIdentityKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Subject: p.Subject}
	u, err := tx.Users().FindByIdentity(ctx, conn.TenantID, conn.ID, p.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if u, err = s.provision(ctx, tx, conn, p); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if u.Blocked {
			return nil, ErrUserBlocked
		}
		if err := s.synchronize(ctx, tx, conn, u, p); err != nil {
			return nil, err
		}
	}
	if err := s.storeTokens(ctx, tx, key, res.Tokens); err != nil {
		return nil, err
	}
	return tx.Users().Get(ctx, conn.TenantID, u.UserID)
}

// identityUserID is the identity's user_id: Google's raw subject, or
// "<connection>|<subject>" for OAuth2 and OIDC.
func identityUserID(conn *store.Connection, sub string) string {
	if conn.Strategy == rules.Google {
		return sub
	}
	return conn.Name + "|" + sub
}

func (s *Service) provision(ctx context.Context, tx store.Store, conn *store.Connection, p Profile) (*store.User, error) {
	now := s.now()
	id := store.FederatedPublicID(conn.Strategy, conn.Name, p.Subject)
	if _, err := tx.Users().Get(ctx, conn.TenantID, id); err == nil {
		return nil, ErrIdentityConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	u := &store.User{TenantID: conn.TenantID, UserID: id, CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: conn.Name, Provider: conn.Strategy, UserID: identityUserID(conn, p.Subject)}}}
	applyRoot(u, p)
	u.Name, u.Nickname = identity.DefaultNames(u.Name, u.Nickname, u.Email, "")
	if p.UserMetadata != nil {
		u.UserMetadata = maps.Clone(p.UserMetadata)
	}
	if err := tx.Users().Create(ctx, u); err != nil {
		return nil, err // ErrConflict: a concurrent first login won
	}
	return u, nil
}

// applyRoot copies the profile's present root fields onto u. A changed email
// without an explicit verification is unverified.
func applyRoot(u *store.User, p Profile) {
	if p.Email != nil {
		if *p.Email != u.Email && p.EmailVerified == nil {
			u.EmailVerified = false
		}
		u.Email = *p.Email
	}
	if p.EmailVerified != nil {
		u.EmailVerified = *p.EmailVerified
	}
	for _, f := range []struct {
		src *string
		dst *string
	}{{p.Name, &u.Name}, {p.Nickname, &u.Nickname}, {p.GivenName, &u.GivenName}, {p.FamilyName, &u.FamilyName}, {p.Picture, &u.Picture}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
}

// synchronize applies the sync policy to an existing owner. A linked
// (secondary) identity updates only its own ProfileData; the primary's root
// profile is untouched.
func (s *Service) synchronize(ctx context.Context, tx store.Store, conn *store.Connection, u *store.User, p Profile) error {
	want := identityUserID(conn, p.Subject)
	var id *store.Identity
	for i := range u.Identities {
		if u.Identities[i].Connection == conn.Name && u.Identities[i].Provider == conn.Strategy && u.Identities[i].UserID == want {
			id = &u.Identities[i]
		}
	}
	if id == nil {
		return fmt.Errorf("%w: index owner lacks the identity", ErrIdentityConflict)
	}
	if id.Linked() {
		pd := maps.Clone(id.ProfileData)
		email, _ := pd["email"].(string)
		if p.Email != nil {
			if *p.Email != email && p.EmailVerified == nil {
				pd["email_verified"] = false
			}
			pd["email"] = *p.Email
		}
		if p.EmailVerified != nil {
			pd["email_verified"] = *p.EmailVerified
		}
		if maps.Equal(pd, id.ProfileData) {
			return nil
		}
		id.ProfileData = pd
	} else {
		if sync := conn.SetUserRootAttributes; sync != "" && sync != rules.SyncOnEachLogin {
			return nil
		}
		before := *u
		applyRoot(u, p)
		if before.Email == u.Email && before.EmailVerified == u.EmailVerified && before.Name == u.Name && before.Nickname == u.Nickname &&
			before.GivenName == u.GivenName && before.FamilyName == u.FamilyName && before.Picture == u.Picture {
			return nil
		}
	}
	u.UpdatedAt = s.now()
	return tx.Users().Update(ctx, u)
}

// storeTokens replaces the identity's sealed token record; an omitted
// refresh token keeps the previous one.
func (s *Service) storeTokens(ctx context.Context, tx store.Store, key store.FederatedIdentityKey, t TokenSet) error {
	if t.AccessToken == "" {
		return nil
	}
	if s.Wrapper == nil {
		return errors.New("federation: no master key wrapper to seal upstream tokens")
	}
	if t.RefreshToken == "" {
		if prev, err := tx.Federation().GetTokens(ctx, key); err == nil {
			if old, err := OpenTokens(s.Wrapper, key, prev); err == nil {
				t.RefreshToken = old.RefreshToken
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	sealed, err := SealTokens(s.Wrapper, key, t)
	if err != nil {
		return err
	}
	return tx.Federation().PutTokens(ctx, key, sealed)
}
