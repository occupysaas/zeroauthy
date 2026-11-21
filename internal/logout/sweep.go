package logout

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

// SweepExpired ends a bounded batch, retaining notification snapshots before
// deletion. A session extended since enumeration is rechecked under its row lock.
func (s *Service) SweepExpired(ctx context.Context, before time.Time, limit int) (int, error) {
	list, ok := s.Store.Sessions().(store.SessionExpiryLister)
	if !ok {
		return 0, store.ErrOIDCLogoutUnavailable
	}
	snapshots, err := list.ListExpired(ctx, before, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, snapshot := range snapshots {
		ended := false
		err := s.Store.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.Tenants().Get(ctx, snapshot.TenantID); err != nil {
				return err
			}
			session, err := tx.Sessions().GetForUpdate(ctx, snapshot.TenantID, snapshot.ID)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if session.ExpiresAt.After(before) && session.IdleExpiresAt.After(before) {
				return nil
			}
			if err := tx.Sessions().Delete(ctx, session.TenantID, session.ID); err != nil {
				return err
			}
			if err := s.WithStore(tx).SessionsEnded(ctx, session.TenantID, []*store.LoginSession{session}, SessionExpired); err != nil {
				return err
			}
			ended = true
			return nil
		})
		if err != nil {
			return n, err
		}
		if ended {
			n++
		}
	}
	return n, nil
}
