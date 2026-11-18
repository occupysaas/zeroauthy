package federation

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// NativeBinding is the trusted configuration/identity snapshot of a native
// Apple first factor. Carry it sealed through MFA and recheck it before mint.
type NativeBinding struct {
	TenantID, ClientID, ConnectionID, BundleID string
	Revision, IdentityEpoch                    int64
}

// NativeAppleEnabled is deliberately independent of custom exchange profiles.
func NativeAppleEnabled(c *store.Client) bool {
	return c != nil && c.NativeSocialLogin["apple"] && c.Mobile != nil && c.Mobile.IOS != nil && c.Mobile.IOS.AppBundleIdentifier != ""
}

// CheckNative rechecks the snapshot through st, which must be the caller's
// transaction for identity or token writes. Client/connection reads take the
// policy writer lock on SQL stores, serializing against reconfiguration.
func (s *FlowService) CheckNative(ctx context.Context, st store.Store, b *NativeBinding) (*store.Connection, error) {
	if b == nil {
		return nil, ErrAttemptStale
	}
	c, err := st.Clients().Get(ctx, b.TenantID, b.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrAttemptStale
	}
	if err != nil {
		return nil, err
	}
	if !NativeAppleEnabled(c) || c.Mobile.IOS.AppBundleIdentifier != b.BundleID {
		return nil, ErrAttemptStale
	}
	conn, err := st.Connections().Get(ctx, b.TenantID, b.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrAttemptStale
	}
	if err != nil {
		return nil, err
	}
	if conn.Strategy != StrategyApple || conn.FederationRevision != b.Revision || !access.ConnectionUsable(c, conn) || len(conn.FederationSecretsSealed) == 0 {
		return nil, ErrAttemptStale
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil || !cfg.AuthenticationActive {
		return nil, ErrConnectionUnusable
	}
	epoch, err := st.Federation().IdentityEpoch(ctx, b.TenantID)
	if err != nil {
		return nil, err
	}
	if epoch != b.IdentityEpoch {
		return nil, ErrAttemptStale
	}
	return conn, nil
}

type NativeAppleInput struct {
	Client     *store.Client
	Connection *store.Connection
	Code       string
	User       *AppleUser
	// BeforeProvision spends the durable first-provider signup budget.
	BeforeProvision func(context.Context) error
	// CommitIdentity validates organization membership inside the same transaction.
	CommitIdentity func(context.Context, store.Store, *store.User, *store.Connection) error
}

// NativeApple redeems one code, with the shared provider transport and network
// policy, then resolves the validated identity under live policy checks. No
// fallback connection or second upstream exchange is attempted.
func (s *FlowService) NativeApple(ctx context.Context, in NativeAppleInput) (*store.User, *NativeBinding, error) {
	if s == nil || s.Providers == nil || in.Connection == nil || !NativeAppleEnabled(in.Client) {
		return nil, nil, ErrConnectionUnusable
	}
	ctx = logscrub.WithCredentials(ctx, in.Code)
	ctx, cancel := context.WithTimeout(ctx, callbackBudget)
	defer cancel()
	conn := in.Connection
	epoch, err := s.Store.Federation().IdentityEpoch(ctx, conn.TenantID)
	if err != nil {
		return nil, nil, err
	}
	b := &NativeBinding{TenantID: conn.TenantID, ClientID: in.Client.ClientID, ConnectionID: conn.ID, BundleID: in.Client.Mobile.IOS.AppBundleIdentifier, Revision: conn.FederationRevision, IdentityEpoch: epoch}
	conn, err = s.CheckNative(ctx, s.Store, b)
	if err != nil {
		return nil, nil, err
	}
	ctx = events.Enrich(ctx, in.Client, conn)
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil {
		return nil, nil, ErrConnectionUnusable
	}
	cfg.ClientID = b.BundleID
	creds, err := OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		return nil, nil, ErrConnectionUnusable
	}
	cache := CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: b.Revision}
	meta, err := s.Providers.AppleMetadata(ctx, cache)
	if err != nil {
		return nil, nil, err
	}
	// Discovery is outbound too: a policy change during it must prevent redemption.
	if _, err = s.CheckNative(ctx, s.Store, b); err != nil {
		return nil, nil, err
	}
	result, err := s.Providers.For(cfg).Exchange(ctx, ExchangeInput{Config: cfg, Cache: cache, Endpoints: meta.Endpoints(), Issuer: meta.Issuer, Code: in.Code, ClientSecret: creds.ClientSecret, Now: s.now(), AppleNative: true, AppleUser: in.User})
	if err != nil {
		return nil, nil, err
	}
	if _, err = s.CheckNative(ctx, s.Store, b); err != nil {
		return nil, nil, err
	}
	if in.BeforeProvision != nil {
		if _, err := s.Store.Users().FindByIdentity(ctx, b.TenantID, b.ConnectionID, result.Profile.Subject); errors.Is(err, store.ErrNotFound) {
			if err := in.BeforeProvision(ctx); err != nil {
				return nil, nil, err
			}
		} else if err != nil {
			return nil, nil, err
		}
	}
	var user *store.User
	commit := func() error {
		return orglogin.WithMembershipEvents(ctx, s.Store, func(ctx context.Context, tx store.Store) error {
			current, err := s.CheckNative(ctx, tx, b)
			if err != nil {
				return err
			}
			user, err = s.ResolveIdentity(ctx, tx, current, result)
			if err != nil {
				return err
			}
			if in.CommitIdentity != nil {
				return in.CommitIdentity(ctx, tx, user, current)
			}
			return nil
		})
	}
	err = commit()
	if errors.Is(err, store.ErrConflict) {
		err = commit()
	}
	if err != nil {
		return nil, nil, err
	}
	return user, b, nil
}
