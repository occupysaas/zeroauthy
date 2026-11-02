package events

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/resourceview"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"reflect"
)

func (s *capture) MFA() store.MFA { return mfa{MFA: s.Store.MFA(), s: s} }

type mfa struct {
	store.MFA
	s *capture
}

func (r mfa) change(ctx context.Context, tid, uid string, fn func(store.MFA) error) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if s.pending == nil {
			return fn(s.Store.MFA())
		}
		u, err := s.Store.Users().GetForUpdate(ctx, tid, uid)
		if err != nil {
			return err
		}
		before, err := s.Store.MFA().ListAuthenticators(ctx, tid, uid)
		if err != nil {
			return err
		}
		if err = fn(s.Store.MFA()); err != nil {
			return err
		}
		after, err := s.Store.MFA().ListAuthenticators(ctx, tid, uid)
		if err != nil {
			return err
		}
		prior := resourceview.Multifactor(before)
		if reflect.DeepEqual(prior, resourceview.Multifactor(after)) {
			return nil
		}
		for _, p := range *s.pending {
			if p.typ == "user.updated" && p.tid == tid && p.id == uid {
				return nil
			}
		}
		*s.pending = append(*s.pending, pendingEvent{ctx: ctx, typ: "user.updated", tid: tid, id: uid, previous: u, previousMFA: prior, mfaOnly: true})
		return nil
	})
}
func (r mfa) CreateAuthenticator(ctx context.Context, a *store.Authenticator) error {
	return r.change(ctx, a.TenantID, a.UserID, func(repo store.MFA) error { return repo.CreateAuthenticator(ctx, a) })
}
func (r mfa) UpdateAuthenticator(ctx context.Context, a *store.Authenticator) error {
	return r.change(ctx, a.TenantID, a.UserID, func(repo store.MFA) error { return repo.UpdateAuthenticator(ctx, a) })
}
func (r mfa) DeleteAuthenticator(ctx context.Context, tid, uid, id string) error {
	return r.change(ctx, tid, uid, func(repo store.MFA) error { return repo.DeleteAuthenticator(ctx, tid, uid, id) })
}
func (r mfa) DeleteUserAuthenticators(ctx context.Context, tid, uid string, types []string) error {
	return r.change(ctx, tid, uid, func(repo store.MFA) error { return repo.DeleteUserAuthenticators(ctx, tid, uid, types) })
}
func (r mfa) DeleteUserMFA(ctx context.Context, tid, uid string) error {
	return r.change(ctx, tid, uid, func(repo store.MFA) error { return repo.DeleteUserMFA(ctx, tid, uid) })
}
