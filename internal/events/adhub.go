package events

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ad_hub.v1 (Plan 38a): the capability and the AD/LDAP store pass through
// the wrapper, also on transaction stores. Without them store.ADHub would
// find no repository behind the wrapper.

func (s *capture) CheckADHubSupport(ctx context.Context) error {
	_, err := store.ADHub(ctx, s.Store)
	return err
}
func (s *capture) CreateADProvisioning(ctx context.Context, p *store.ADProvisioning) error {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.CreateADProvisioning(ctx, p)
}
func (s *capture) GetADProvisioning(ctx context.Context, tid, cid string) (*store.ADProvisioning, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.GetADProvisioning(ctx, tid, cid)
}
func (s *capture) FindADProvisioning(ctx context.Context, tid, hash string) (*store.ADProvisioning, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.FindADProvisioning(ctx, tid, hash)
}
func (s *capture) PutADHubSession(ctx context.Context, sess *store.ADHubSession) error {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.PutADHubSession(ctx, sess)
}
func (s *capture) DeleteADHubSession(ctx context.Context, tid, cid, sid string) error {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.DeleteADHubSession(ctx, tid, cid, sid)
}
func (s *capture) ListADHubSessions(ctx context.Context, tid, cid string, seenAfter time.Time) ([]*store.ADHubSession, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.ListADHubSessions(ctx, tid, cid, seenAfter)
}
func (s *capture) PurgeADHubSessions(ctx context.Context, before time.Time, limit int) (int, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return 0, err
	}
	return repo.PurgeADHubSessions(ctx, before, limit)
}
