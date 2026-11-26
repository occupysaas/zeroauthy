package memory

import (
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The memory store implements store.MyOrgStore (Plan 42b).

func (s *Store) PutMyOrgClientConfig(_ context.Context, c *store.MyOrgClientConfig) error {
	if c == nil || c.TenantID == "" || c.ClientID == "" || len(c.Doc) == 0 {
		return store.ErrInvalid
	}
	s.lock()
	defer s.unlock()
	if _, ok := s.clients[key{c.TenantID, c.ClientID}]; !ok {
		return store.ErrNotFound
	}
	s.myOrgConfigs[key{c.TenantID, c.ClientID}] = c.Clone()
	return nil
}

func (s *Store) GetMyOrgClientConfig(_ context.Context, tid, cid string) (*store.MyOrgClientConfig, error) {
	s.readLock()
	defer s.readUnlock()
	c, ok := s.myOrgConfigs[key{tid, cid}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return c.Clone(), nil
}

func (s *Store) DeleteMyOrgClientConfig(_ context.Context, tid, cid string) error {
	s.lock()
	defer s.unlock()
	delete(s.myOrgConfigs, key{tid, cid})
	return nil
}

func (s *Store) SetMyOrgRoleVisible(_ context.Context, tid, rid string, visible bool) error {
	s.lock()
	defer s.unlock()
	if _, ok := s.roles[key{tid, rid}]; !ok {
		return store.ErrNotFound
	}
	if visible {
		s.myOrgRoles[key{tid, rid}] = true
	} else {
		delete(s.myOrgRoles, key{tid, rid})
	}
	return nil
}

func (s *Store) ListMyOrgVisibleRoles(_ context.Context, tid string) ([]string, error) {
	s.readLock()
	defer s.readUnlock()
	out := []string{}
	for k := range s.myOrgRoles {
		if k.tenant == tid {
			out = append(out, k.id)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) PutDomainClaim(_ context.Context, tid, org, id string, created time.Time) error {
	s.lock()
	defer s.unlock()
	if s.orgDomains[orgIIKey{tid, org, id}] == nil {
		return store.ErrNotFound
	}
	s.myOrgClaims[orgIIKey{tid, org, id}] = created.UTC()
	return nil
}

func (s *Store) DomainClaims(_ context.Context, tid, org string) (map[string]time.Time, error) {
	s.readLock()
	defer s.readUnlock()
	out := map[string]time.Time{}
	for k, v := range s.myOrgClaims {
		if k.tenant == tid && k.org == org {
			out[k.id] = v
		}
	}
	return out, nil
}

func (s *Store) DeleteDomainClaim(_ context.Context, tid, org, id string) error {
	s.lock()
	defer s.unlock()
	delete(s.myOrgClaims, orgIIKey{tid, org, id})
	return nil
}

func (s *Store) VerifiedDomainOrganizations(_ context.Context, tid, domain string) ([]string, error) {
	s.readLock()
	defer s.readUnlock()
	out := []string{}
	for k, v := range s.orgDomains {
		if k.tenant == tid && v.Domain == domain && v.Status == "verified" && !slices.Contains(out, k.org) {
			out = append(out, k.org)
		}
	}
	slices.Sort(out)
	return out, nil
}
