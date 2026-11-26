package events

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ciba.v1 (Plan 41c): the CIBA methods and capability pass through the
// wrapper, also on transaction stores. Without them store.CIBA would treat
// the wrapper as unsupported.

func (s *capture) CheckCIBASupport(ctx context.Context) error {
	_, err := store.CIBA(ctx, s.Store)
	return err
}

func (s *capture) CreateCIBARequest(ctx context.Context, r *store.CIBARequest) error {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.CreateCIBARequest(ctx, r)
}

func (s *capture) GetCIBARequest(ctx context.Context, tid, idHash string) (*store.CIBARequest, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.GetCIBARequest(ctx, tid, idHash)
}

func (s *capture) GetCIBARequestByTicket(ctx context.Context, tid, ticketHash string) (*store.CIBARequest, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.GetCIBARequestByTicket(ctx, tid, ticketHash)
}

func (s *capture) DecideCIBARequest(ctx context.Context, tid, idHash string, dec store.CIBADecision) (*store.CIBARequest, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.DecideCIBARequest(ctx, tid, idHash, dec)
}

func (s *capture) PollCIBARequest(ctx context.Context, tid, idHash, clientID string, at time.Time) (store.CIBAPoll, *store.CIBARequest, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return 0, nil, err
	}
	return repo.PollCIBARequest(ctx, tid, idHash, clientID, at)
}

func (s *capture) CountPendingCIBARequests(ctx context.Context, tid string, now time.Time) (int, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return 0, err
	}
	return repo.CountPendingCIBARequests(ctx, tid, now)
}

func (s *capture) DeleteExpiredCIBARequests(ctx context.Context, before time.Time) (int, error) {
	repo, err := store.CIBA(ctx, s.Store)
	if err != nil {
		return 0, err
	}
	return repo.DeleteExpiredCIBARequests(ctx, before)
}
