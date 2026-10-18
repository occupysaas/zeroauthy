// Package system runs the reserved `system` tenant: zeroauthy's own
// tenant, whose users are the console operators (design §4.1).
//
// Ensure creates or repairs it at every start; CreateOperator invites an
// operator with a one-time setup link (`zeroauthy admin create`); Bootstrap
// does that once for automated installs (bootstrap.admin_email).
package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const (
	// ConsoleClientID is the console's SPA client in the system tenant.
	ConsoleClientID = "zeroauthy-console"
	// OperatorsConnection is the database connection operators sign in with.
	OperatorsConnection = "Operators"
	// ManagementAudience is the API whose tokens operators present to every
	// tenant's Management API.
	ManagementAudience = tenant.ManagementAudience
	// SetupLinkLifetime is how long an operator's setup link works.
	SetupLinkLifetime = time.Hour
	// operatorPasswordMinLength is the Operators connection's password policy.
	operatorPasswordMinLength = 12
)

// Config is what Ensure needs from the server configuration.
type Config struct {
	// Host is the system tenant's host, tenant.SystemHost(base_domain,
	// system_host). It is stored as the tenant's only domain.
	Host string
	// Wrapper seals the tenant's signing keys.
	Wrapper keys.Wrapper
	// Now defaults to time.Now.
	Now func() time.Time
}

// Ensure creates the system tenant, or brings it back to its defined state:
// the domain Config.Host, signing keys, the Operators connection (enabled
// only for the console, no sign-up), the console client and the
// urn:zeroauthy:management resource server. It is idempotent. Operators and
// their users are never touched.
//
// It refuses a tenant named `system` that zeroauthy did not create
// (Reserved unset), and a host already used by another tenant.
func Ensure(ctx context.Context, st store.Store, cfg Config) (*store.Tenant, error) {
	if cfg.Host == "" {
		return nil, errors.New("system: the system host is empty; set server.system_host or server.base_domain")
	}
	host := tenant.NormalizeHost(cfg.Host)
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	var out *store.Tenant
	apply := func() error {
		return st.WithTx(ctx, func(tx store.Store) error {
			tn, err := ensure(ctx, tx, host, now().UTC(), cfg.Wrapper)
			out = tn
			return err
		})
	}
	err := apply()
	if errors.Is(err, store.ErrConflict) {
		// Another replica created it first; the retry updates its rows.
		err = apply()
	}
	if errors.Is(err, store.ErrConflict) {
		if other, gerr := st.Tenants().GetByDomain(ctx, host); gerr == nil && other.Name != tenant.SystemName {
			return nil, fmt.Errorf("system: the system host %q is already used by tenant %q; choose another server.system_host", host, other.Name)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}
	return out, nil
}

func ensure(ctx context.Context, st store.Store, host string, now time.Time, w keys.Wrapper) (*store.Tenant, error) {
	if existing, err := st.Tenants().GetByName(ctx, tenant.SystemName); err == nil && !existing.Reserved {
		return nil, fmt.Errorf("a tenant named %q exists that is not zeroauthy's system tenant; rename or delete it", tenant.SystemName)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if other, err := st.Tenants().GetByDomain(ctx, host); err == nil && other.Name != tenant.SystemName {
		return nil, fmt.Errorf("the system host %q is already used by tenant %q; choose another server.system_host", host, other.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	tn, err := tenantsetup.UpsertTenant(ctx, st, tenant.SystemName, now, func(t *store.Tenant) error {
		t.Reserved, t.Seeded = true, false
		t.Domains = []string{host}
		t.DefaultDirectory = OperatorsConnection
		if t.FriendlyName == "" {
			t.FriendlyName = "zeroauthy"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A storage plugin that predates the field drops it silently; without
	// it the next start could not tell this tenant from a foreign one.
	if stored, err := st.Tenants().Get(ctx, tn.ID); err != nil {
		return nil, err
	} else if !stored.Reserved {
		return nil, errors.New("the storage did not keep Tenant.reserved; a storage plugin older than this zeroauthy version must be upgraded")
	}
	if err := tenantsetup.SigningKeys(ctx, st, w, tn.ID); err != nil {
		return nil, err
	}
	origin := "https://" + host
	err = tenantsetup.UpsertResourceServer(ctx, st, tn.ID, ManagementAudience, now, func(rs *store.ResourceServer) error {
		rs.Name, rs.SigningAlg = "zeroauthy Management", "RS256"
		rs.Scopes = nil
		rs.AllowOfflineAccess = true
		rs.SkipConsentForVerifiableFirstPartyClients = true
		// Operator tokens are user tokens; no machine client may get one.
		rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyDenyAll}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = tenantsetup.UpsertClient(ctx, st, tn.ID, ConsoleClientID, now, func(c *store.Client, _ bool) error {
		c.Name, c.AppType = "zeroauthy console", store.AppTypeSPA
		c.TokenEndpointAuthMethod, c.Secrets = store.AuthMethodNone, nil
		c.GrantTypes = []string{"authorization_code", "refresh_token"}
		c.Callbacks = []string{origin + "/admin/callback"}
		c.AllowedLogoutURLs = []string{origin + "/admin/"}
		c.WebOrigins = []string{origin}
		c.AllowedOrigins = nil
		c.IsFirstParty, c.ThirdPartySecurityMode = true, ""
		c.RedirectionPolicy = store.RedirectionPolicyAllowAlways
		c.RequirePushedAuthorizationRequests = false
		c.SkipNonVerifiableCallbackURIConfirmationPrompt = nil
		c.RefreshToken = store.RefreshTokenPolicy{Rotating: true, Expiring: true}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = tenantsetup.UpsertConnection(ctx, st, tn.ID, OperatorsConnection, now, func(c *store.Connection) error {
		c.Strategy = store.StrategyDatabase
		c.EnabledClients = []string{ConsoleClientID}
		c.IsDomainConnection = false
		c.DisableSignup = true // operators are invited, never self-registered
		c.RequiresUsername = false
		if c.PasswordPolicy.MinLength < operatorPasswordMinLength {
			c.PasswordPolicy.MinLength = operatorPasswordMinLength
		}
		c.EnabledDatabaseCustomization, c.ImportMode = false, false
		c.CustomScripts, c.ConfigurationSealed = nil, nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tn, nil
}

// Tenant returns the system tenant, or an error asking for Ensure to run.
func Tenant(ctx context.Context, st store.Store) (*store.Tenant, error) {
	tn, err := st.Tenants().GetByName(ctx, tenant.SystemName)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && !tn.Reserved:
		return nil, errors.New("system: the system tenant does not exist; start the server once (or run any zeroauthy command that prepares it) first")
	case err != nil:
		return nil, err
	case len(tn.Domains) == 0:
		return nil, errors.New("system: the system tenant has no host")
	}
	return tn, nil
}

// CreateOperator makes email an operator of every tenant and returns a
// one-time setup link, valid for SetupLinkLifetime, where they choose a
// password. A new user has no password until then. Calling it again for the
// same address keeps the user and the operator's tenants and issues a new
// link; earlier unused links stay valid until they expire.
func CreateOperator(ctx context.Context, st store.Store, email string) (string, error) {
	return createOperator(ctx, st, email, false)
}

// errBootstrapped ends a bootstrap transaction that finds an operator.
var errBootstrapped = errors.New("system: an operator already exists")

// createOperator is CreateOperator. With onlyFirst it creates nothing when
// the system tenant has an operator, checked inside the same transaction.
func createOperator(ctx context.Context, st store.Store, email string, onlyFirst bool) (string, error) {
	email = identity.NormalizeLogin(strings.TrimSpace(email))
	if err := identity.CheckEmail(email); err != nil {
		return "", fmt.Errorf("system: %q is not a valid email address", email)
	}
	tn, err := Tenant(ctx, st)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	var raw string
	err = st.WithTx(ctx, func(tx store.Store) error {
		if onlyFirst {
			// Rewriting the tenant row unchanged locks it, so concurrent
			// bootstraps run one after another and the second sees the
			// first one's operator.
			locked, err := tx.Tenants().Get(ctx, tn.ID)
			if err != nil {
				return err
			}
			if err := tx.Tenants().Update(ctx, locked); err != nil {
				return err
			}
			ops, err := tx.Operators().List(ctx, tn.ID)
			if err != nil {
				return err
			}
			if len(ops) > 0 {
				return errBootstrapped
			}
		}
		u, err := tx.Users().FindByLogin(ctx, tn.ID, OperatorsConnection, email)
		if errors.Is(err, store.ErrNotFound) {
			id := secrets.RandomHex(12)
			u = &store.User{
				TenantID: tn.ID, UserID: store.StrategyDatabase + "|" + id,
				Email: email, Name: email, Nickname: strings.SplitN(email, "@", 2)[0],
				Identities: []store.Identity{{Connection: OperatorsConnection, Provider: store.StrategyDatabase, UserID: id}},
				CreatedAt:  now, UpdatedAt: now,
			}
			err = tx.Users().Create(ctx, u)
		}
		if err != nil {
			return err
		}
		op, err := tx.Operators().Get(ctx, tn.ID, u.UserID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			op = &store.Operator{TenantID: tn.ID, UserID: u.UserID, Tenants: []string{store.OperatorAllTenants}, CreatedAt: now, UpdatedAt: now}
			if err := tx.Operators().Upsert(ctx, op); err != nil {
				return err
			}
		case err != nil:
			return err
		}
		raw, err = dbconn.IssueTicket(ctx, tx, tn.ID, u.UserID, OperatorsConnection, ConsoleClientID, "", now, SetupLinkLifetime)
		return err
	})
	if err != nil {
		if errors.Is(err, errBootstrapped) {
			return "", err
		}
		return "", fmt.Errorf("system: create operator: %w", err)
	}
	return dbconn.ResetLink(tenant.Resolved{Tenant: tn, Host: tn.Domains[0]}.Issuer(), raw), nil
}

// Bootstrap creates the operator email and returns its setup link when the
// system tenant has no operator yet. Otherwise, or when email is empty, it
// returns "" and does nothing, so it runs at every start. The check and the
// creation share one transaction; a conflict there means another replica
// bootstrapped at the same moment, which is also "" and no error.
func Bootstrap(ctx context.Context, st store.Store, email string) (string, error) {
	if email == "" {
		return "", nil
	}
	link, err := createOperator(ctx, st, email, true)
	if errors.Is(err, errBootstrapped) || errors.Is(err, store.ErrConflict) {
		return "", nil
	}
	return link, err
}
