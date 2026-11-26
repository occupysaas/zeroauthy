package storeplugin

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// my_org.v1 (Plan 42b): the capability and the My Organization store pass
// through the wrapper, also on transaction stores. Without them store.MyOrg
// would find no repository behind the wrapper.

func (s *opened) CheckMyOrgSupport(ctx context.Context) error {
	_, err := store.MyOrg(ctx, s.Store)
	return err
}
func (s *opened) PutMyOrgClientConfig(ctx context.Context, c *store.MyOrgClientConfig) error {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.PutMyOrgClientConfig(ctx, c)
}
func (s *opened) GetMyOrgClientConfig(ctx context.Context, tid, cid string) (*store.MyOrgClientConfig, error) {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.GetMyOrgClientConfig(ctx, tid, cid)
}
func (s *opened) DeleteMyOrgClientConfig(ctx context.Context, tid, cid string) error {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.DeleteMyOrgClientConfig(ctx, tid, cid)
}
func (s *opened) SetMyOrgRoleVisible(ctx context.Context, tid, rid string, visible bool) error {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.SetMyOrgRoleVisible(ctx, tid, rid, visible)
}
func (s *opened) ListMyOrgVisibleRoles(ctx context.Context, tid string) ([]string, error) {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.ListMyOrgVisibleRoles(ctx, tid)
}
func (s *opened) PutDomainClaim(ctx context.Context, tid, org, id string, created time.Time) error {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.PutDomainClaim(ctx, tid, org, id, created)
}
func (s *opened) DomainClaims(ctx context.Context, tid, org string) (map[string]time.Time, error) {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.DomainClaims(ctx, tid, org)
}
func (s *opened) DeleteDomainClaim(ctx context.Context, tid, org, id string) error {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return err
	}
	return repo.DeleteDomainClaim(ctx, tid, org, id)
}
func (s *opened) VerifiedDomainOrganizations(ctx context.Context, tid, domain string) ([]string, error) {
	repo, err := store.MyOrg(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	return repo.VerifiedDomainOrganizations(ctx, tid, domain)
}
