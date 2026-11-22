package events

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *capture) CheckEventsSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.EventsSupporter); ok {
		return p.CheckEventsSupport(ctx)
	}
	_, err := s.Store.Events().LatestEventSeq(ctx, "")
	return err
}
func (s *capture) EventsSupported() bool {
	if p, ok := s.Store.(store.EventsSupporter); ok {
		return p.EventsSupported()
	}
	switch s.Store.Events().(type) {
	case store.UnimplementedEvents, *store.UnimplementedEvents:
		return false
	}
	return true
}
func (s *capture) CheckRBACSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.RBACSupporter); ok {
		return p.CheckRBACSupport(ctx)
	}
	return nil
}
func (s *capture) CheckActionsSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.ActionsSupporter); ok {
		return p.CheckActionsSupport(ctx)
	}
	return nil
}
func (s *capture) CheckOrganizationsSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.OrganizationsSupporter); ok {
		return p.CheckOrganizationsSupport(ctx)
	}
	return nil
}
func (s *capture) OrganizationsSupported() bool {
	if p, ok := s.Store.(store.OrganizationsSupporter); ok {
		return p.OrganizationsSupported()
	}
	return true
}
func (s *capture) CheckOrganizationsIISupport(ctx context.Context) error {
	if p, ok := s.Store.(store.OrganizationsIISupporter); ok {
		return p.CheckOrganizationsIISupport(ctx)
	}
	return nil
}
func (s *capture) OrganizationsIISupported() bool {
	if p, ok := s.Store.(store.OrganizationsIISupporter); ok {
		return p.OrganizationsIISupported()
	}
	return true
}
func (s *capture) CheckLogsSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.LogsSupporter); ok {
		return p.CheckLogsSupport(ctx)
	}
	return nil
}
func (s *capture) LogsSupported() bool {
	if p, ok := s.Store.(store.LogsSupporter); ok {
		return p.LogsSupported()
	}
	return true
}
func (s *capture) MicrosoftFederationSupported(ctx context.Context) error {
	if p, ok := s.Store.(store.MicrosoftFederationSupporter); ok {
		return p.MicrosoftFederationSupported(ctx)
	}
	return store.ErrFederationUnavailable
}

func (s *capture) CheckRefreshTokensIISupport(ctx context.Context) error {
	return store.CheckRefreshTokensIISupport(ctx, s.Store)
}
func (s *capture) GitHubFederationSupported(ctx context.Context) error {
	if p, ok := s.Store.(store.GitHubFederationSupporter); ok {
		return p.GitHubFederationSupported(ctx)
	}
	return store.ErrFederationUnavailable
}

// SAML (Plan 37a): the capability and the replay store pass through, also
// on transaction stores, where SP logins consume assertion IDs.
func (s *capture) CheckSAMLSupport(ctx context.Context) error {
	return store.CheckSAMLSupport(ctx, s.Store)
}
func (s *capture) UseSAMLAssertion(ctx context.Context, tid, connection, id string, exp, now time.Time) error {
	repo, ok := s.Store.(store.SAMLReplayStore)
	if !ok {
		return store.ErrSAMLUnavailable
	}
	return repo.UseSAMLAssertion(ctx, tid, connection, id, exp, now)
}
func (s *capture) PurgeSAMLAssertions(ctx context.Context, before time.Time, limit int) (int, error) {
	repo, ok := s.Store.(store.SAMLReplayStore)
	if !ok {
		return 0, store.ErrSAMLUnavailable
	}
	return repo.PurgeSAMLAssertions(ctx, before, limit)
}
