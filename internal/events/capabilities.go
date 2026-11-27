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
func (s *capture) SocialFederationSupported(ctx context.Context) error {
	if p, ok := s.Store.(store.SocialFederationSupporter); ok {
		return p.SocialFederationSupported(ctx)
	}
	return store.ErrFederationUnavailable
}
func (s *capture) GitHubFederationSupported(ctx context.Context) error {
	if p, ok := s.Store.(store.GitHubFederationSupporter); ok {
		return p.GitHubFederationSupported(ctx)
	}
	return store.ErrFederationUnavailable
}

// DirectorySupported passes scim.v1 (Plan 37c) through.
func (s *capture) DirectorySupported() bool { return store.DirectoryAvailable(s.Store) }

// SelfServiceSupported passes scim.v1 version 2 (Plan 37c Phase B) through.
func (s *capture) SelfServiceSupported() bool { return store.SelfServiceAvailable(s.Store) }

// DirectorySyncSupported passes scim.v1 version 3 (Plan 37c Phase C) through.
func (s *capture) DirectorySyncSupported() bool { return store.DirectorySyncAvailable(s.Store) }

// CheckCIMDSupport passes cimd.v1 (Plan 41b) through.
func (s *capture) CheckCIMDSupport(ctx context.Context) error {
	return store.CheckCIMDSupport(ctx, s.Store)
}

// CheckWSFedSupport passes wsfed.v1 (Plan 37b) through.
func (s *capture) CheckWSFedSupport(ctx context.Context) error {
	return store.CheckWSFedSupport(ctx, s.Store)
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

// The optional interfaces below must be forwarded explicitly: the embedded
// store.Store does not carry them, and the production store is always
// wrapped. Without a supporter the answers match the gRPC server's defaults.

func (s *capture) CheckOIDCLogoutSupport(ctx context.Context) error {
	return store.CheckOIDCLogoutSupport(ctx, s.Store)
}
func (s *capture) CheckClientCredentialsSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.ClientCredentialsSupporter); ok {
		return p.CheckClientCredentialsSupport(ctx)
	}
	return nil
}
func (s *capture) ClientCredentialsSupported() bool {
	if p, ok := s.Store.(store.ClientCredentialsSupporter); ok {
		return p.ClientCredentialsSupported()
	}
	switch s.Store.ClientCredentials().(type) {
	case store.UnimplementedClientCredentials, *store.UnimplementedClientCredentials:
		return false
	}
	return true
}
func (s *capture) ConnectionKeysSupported() bool {
	if p, ok := s.Store.(store.ConnectionKeysSupporter); ok {
		return p.ConnectionKeysSupported()
	}
	switch s.Store.ConnectionKeys().(type) {
	case store.UnimplementedConnectionKeys, *store.UnimplementedConnectionKeys:
		return false
	}
	return true
}
func (s *capture) CheckMFASupport(ctx context.Context) error {
	if p, ok := s.Store.(store.MFASupporter); ok {
		return p.CheckMFASupport(ctx)
	}
	return nil
}
func (s *capture) MFASupported() bool {
	if p, ok := s.Store.(store.MFASupporter); ok {
		return p.MFASupported()
	}
	switch s.Store.MFA().(type) {
	case store.UnimplementedMFA, *store.UnimplementedMFA:
		return false
	}
	return true
}
func (s *capture) CheckPhoneSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.PhoneSupporter); ok {
		return p.CheckPhoneSupport(ctx)
	}
	return nil
}
func (s *capture) PhoneSupported() bool {
	if p, ok := s.Store.(store.PhoneSupporter); ok {
		return p.PhoneSupported()
	}
	switch s.Store.Phone().(type) {
	case store.UnimplementedPhone, *store.UnimplementedPhone:
		return false
	}
	return true
}
func (s *capture) UseGlobalRevocationJTI(ctx context.Context, tid, connection, jti string, exp, now time.Time) error {
	repo, ok := s.Store.(store.GlobalRevocationStore)
	if !ok {
		return store.ErrOIDCLogoutUnavailable
	}
	return repo.UseGlobalRevocationJTI(ctx, tid, connection, jti, exp, now)
}
func (s *capture) PurgeGlobalRevocationJTIs(ctx context.Context, before time.Time, limit int) (int, error) {
	repo, ok := s.Store.(store.GlobalRevocationStore)
	if !ok {
		return 0, store.ErrOIDCLogoutUnavailable
	}
	return repo.PurgeGlobalRevocationJTIs(ctx, before, limit)
}
func (s *capture) FindByFederatedEmail(ctx context.Context, tid, connection, email string) (*store.User, error) {
	repo, ok := s.Store.(store.GlobalRevocationStore)
	if !ok {
		return nil, store.ErrOIDCLogoutUnavailable
	}
	return repo.FindByFederatedEmail(ctx, tid, connection, email)
}
