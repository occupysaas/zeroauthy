package seed

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// Apply upserts everything in f. It never deletes.
//
// A transaction that fails with store.ErrConflict is retried once: two
// replicas seeding a fresh shared database both see a tenant (or client, or
// user) as missing, and the loser's insert conflicts. On the retry the
// winner's rows exist and are updated instead.
func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper) error {
	err := apply(ctx, st, f, now, w)
	if errors.Is(err, store.ErrConflict) {
		err = apply(ctx, st, f, now, w)
	}
	return err
}

func apply(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper) error {
	if now == nil {
		now = time.Now
	}
	return st.WithTx(ctx, func(tx store.Store) error {
		for _, t := range f.Tenants {
			if err := applyTenant(ctx, tx, t, now().UTC(), w); err != nil {
				return fmt.Errorf("seed: tenant %q: %w", t.Name, err)
			}
		}
		return nil
	})
}

func applyTenant(ctx context.Context, st store.Store, in Tenant, now time.Time, w keys.Wrapper) error {
	domains := make([]string, len(in.Domains))
	for i, d := range in.Domains {
		domains[i] = tenant.NormalizeHost(d)
	}
	tn, err := tenantsetup.UpsertTenant(ctx, st, in.Name, now, func(tn *store.Tenant) error {
		tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
		tn.AllowedLogoutURLs = slices.Clone(in.AllowedLogoutURLs)
		tn.EnabledLocales = slices.Clone(in.EnabledLocales)
		tn.CustomText = in.CustomText
		tn.SessionLifetime, tn.IdleSessionLifetime = in.SessionLifetime, in.IdleSessionLifetime
		tn.Branding = store.Branding{LogoURL: in.Branding.LogoURL, PrimaryColor: strings.ToLower(in.Branding.PrimaryColor)}
		tn.DefaultDirectory = in.DefaultDirectory
		tn.SkipNonVerifiableCallbackURIConfirmationPrompt = in.SkipNonVerifiableCallbackURIConfirmationPrompt
		tn.UseScopeDescriptionsForConsent = in.UseScopeDescriptionsForConsent
		tn.PushedAuthorizationRequestsSupported = in.PushedAuthorizationRequestsSupported
		tn.DeviceFlowCharset, tn.DeviceFlowMask = in.DeviceFlow.Charset, in.DeviceFlow.Mask
		tn.Seeded = true
		return nil
	})
	if err != nil {
		return err
	}

	for _, rs := range in.ResourceServers {
		if err := applyResourceServer(ctx, st, tn.ID, rs, now); err != nil {
			return fmt.Errorf("resource server %q: %w", rs.Identifier, err)
		}
	}
	for _, c := range in.Clients {
		if err := applyClient(ctx, st, tn.ID, c, now, w); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, g := range in.ClientGrants {
		if err := applyClientGrant(ctx, st, tn.ID, g, now); err != nil {
			return fmt.Errorf("client grant %q → %q: %w", g.ClientID, g.Audience, err)
		}
	}
	for _, c := range in.Connections {
		if err := applyConnection(ctx, st, tn.ID, c, now, w); err != nil {
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}
	}
	for _, u := range in.Users {
		if err := applyUser(ctx, st, tn.ID, u, now); err != nil {
			return fmt.Errorf("user %q: %w", u.Email, err)
		}
	}
	return nil
}

func applyResourceServer(ctx context.Context, st store.Store, tenantID string, in ResourceServer, now time.Time) error {
	scopes := make([]store.Scope, len(in.Scopes))
	for i, s := range in.Scopes {
		scopes[i] = store.Scope{Value: s.Value, Description: s.Description}
	}
	return tenantsetup.UpsertResourceServer(ctx, st, tenantID, in.Identifier, now, func(rs *store.ResourceServer) error {
		rs.Name, rs.Scopes, rs.SigningAlg = in.Name, scopes, "RS256"
		rs.TokenLifetime, rs.AllowOfflineAccess = in.TokenLifetime, in.AllowOfflineAccess
		rs.SkipConsentForVerifiableFirstPartyClients = *in.SkipConsentForVerifiableFirstPartyClients
		rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: in.SubjectTypeAuthorization.User.Policy, Client: in.SubjectTypeAuthorization.Client.Policy}
		return nil
	})
}

func applyClient(ctx context.Context, st store.Store, tenantID string, in Client, now time.Time, w keys.Wrapper) error {
	return tenantsetup.UpsertClient(ctx, st, tenantID, in.ClientID, now, func(c *store.Client, create bool) error {
		return setClient(c, create, in, now, w)
	})
}

func setClient(c *store.Client, create bool, in Client, now time.Time, w keys.Wrapper) error {
	if !create && (c.IsFirstParty != *in.IsFirstParty || c.ThirdPartySecurityMode != in.ThirdPartySecurityMode) {
		return errors.New("is_first_party and third_party_security_mode cannot change after creation; use a new client_id")
	}
	c.IsFirstParty, c.ThirdPartySecurityMode = *in.IsFirstParty, in.ThirdPartySecurityMode
	c.RedirectionPolicy = in.RedirectionPolicy
	c.RequirePushedAuthorizationRequests = in.RequirePushedAuthorizationRequests
	c.SkipNonVerifiableCallbackURIConfirmationPrompt = nil
	if p := in.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		v := *p
		c.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
	c.Name, c.AppType = in.Name, store.AppType(in.AppType)
	c.TokenEndpointAuthMethod = in.TokenEndpointAuthMethod
	c.GrantTypes = slices.Clone(in.GrantTypes)
	c.Callbacks, c.AllowedLogoutURLs = slices.Clone(in.Callbacks), slices.Clone(in.AllowedLogoutURLs)
	c.WebOrigins, c.AllowedOrigins = slices.Clone(in.WebOrigins), slices.Clone(in.AllowedOrigins)
	c.IDTokenLifetime = in.IDTokenLifetime
	c.RefreshToken = store.RefreshTokenPolicy{
		Rotating:          in.RefreshToken.RotationType == "rotating",
		Leeway:            in.RefreshToken.Leeway,
		Expiring:          in.RefreshToken.ExpirationType == "expiring",
		TokenLifetime:     in.RefreshToken.TokenLifetime,
		IdleTokenLifetime: in.RefreshToken.IdleTokenLifetime,
	}

	public := c.TokenEndpointAuthMethod == store.AuthMethodNone
	switch {
	case public:
		c.Secrets = nil
	case in.ClientSecret == "":
		// Keep whatever is stored: a seed without client_secret must not
		// wipe a secret set earlier or through the Management API.
		// A client with no stored secret (new, or public until now) needs one.
		if len(c.Secrets) == 0 {
			return fmt.Errorf("client_secret is required for %s when the client has no stored secret", c.TokenEndpointAuthMethod)
		}
	case !sealedSecretMatches(w, c, in.ClientSecret):
		// A matching legacy hash is replaced too: the seed carries the
		// plaintext, so the client moves to the sealed form (D-0038).
		sealed, err := keys.SealClientSecret(w, c.TenantID, c.ClientID, in.ClientSecret)
		if err != nil {
			return err
		}
		c.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: now}}
	}
	return nil
}

// sealedSecretMatches reports whether one of the client's sealed secrets
// opens to plaintext, so an unchanged seed does not re-seal on every apply.
// Expiry is ignored: a secret named in the seed is the client's secret.
func sealedSecretMatches(w keys.Wrapper, c *store.Client, plaintext string) bool {
	for _, s := range c.Secrets {
		if s.Sealed == nil {
			continue
		}
		got, err := keys.OpenClientSecret(w, c.TenantID, c.ClientID, s.Sealed)
		if err == nil && subtle.ConstantTimeCompare([]byte(got), []byte(plaintext)) == 1 {
			return true
		}
	}
	return false
}

func applyClientGrant(ctx context.Context, st store.Store, tenantID string, in ClientGrant, now time.Time) error {
	g, err := st.ClientGrants().Find(ctx, tenantID, in.ClientID, in.Audience, in.SubjectType)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return st.ClientGrants().Create(ctx, &store.ClientGrant{
			TenantID: tenantID, ID: "cgr_" + secrets.RandomString(24),
			ClientID: in.ClientID, Audience: in.Audience, Scopes: slices.Clone(in.Scopes),
			SubjectType: in.SubjectType, CreatedAt: now,
		})
	case err != nil:
		return err
	default:
		g.Scopes = slices.Clone(in.Scopes)
		return st.ClientGrants().Update(ctx, g)
	}
}

func applyConnection(ctx context.Context, st store.Store, tenantID string, in Connection, now time.Time, w keys.Wrapper) error {
	return tenantsetup.UpsertConnection(ctx, st, tenantID, in.Name, now, func(c *store.Connection) error {
		return setConnection(c, in, w)
	})
}

func setConnection(c *store.Connection, in Connection, w keys.Wrapper) error {
	c.Strategy = in.Strategy
	c.IsDomainConnection = in.IsDomainConnection
	c.EnabledClients = slices.Clone(in.EnabledClients)
	c.DisableSignup, c.RequiresUsername = in.DisableSignup, in.RequiresUsername
	c.PasswordPolicy = store.PasswordPolicy{MinLength: in.PasswordPolicy.MinLength, RequireCharacterClasses: in.PasswordPolicy.RequireCharacterClasses}
	c.EnabledDatabaseCustomization, c.ImportMode = in.EnabledDatabaseCustomization, in.ImportMode
	c.SetUserRootAttributes = in.SetUserRootAttributes
	c.CustomScripts = maps.Clone(in.CustomScripts)
	// The ID is final here (generated or existing), so the AAD stays valid
	// across re-applies. Configuration is always re-sealed: sealing is
	// randomized, so there is nothing to compare, and removing it clears it.
	c.ConfigurationSealed = nil
	if len(in.Configuration) > 0 {
		if w == nil {
			return errors.New("a master key wrapper is required to seal configuration")
		}
		sealed, err := keys.SealConnectionConfig(w, c.TenantID, c.ID, in.Configuration)
		if err != nil {
			return err
		}
		c.ConfigurationSealed = sealed
	}
	return nil
}

func applyUser(ctx context.Context, st store.Store, tenantID string, in User, now time.Time) error {
	u, err := st.Users().FindByLogin(ctx, tenantID, in.Connection, in.Email)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		id := secrets.RandomHex(12)
		u = &store.User{
			TenantID: tenantID, UserID: store.StrategyDatabase + "|" + id, CreatedAt: now,
			Identities: []store.Identity{{Connection: in.Connection, Provider: store.StrategyDatabase, UserID: id}},
		}
	}
	u.Email, u.EmailVerified, u.Username = in.Email, in.EmailVerified, in.Username
	u.Name, u.Nickname, u.Picture, u.Blocked = in.Name, in.Nickname, in.Picture, in.Blocked
	u.GivenName, u.FamilyName = in.GivenName, in.FamilyName
	if u.Name == "" {
		u.Name = in.Email
	}
	if u.Nickname == "" {
		u.Nickname = strings.SplitN(in.Email, "@", 2)[0]
	}
	u.UpdatedAt = now
	for i := range u.Identities {
		if u.Identities[i].Connection != in.Connection {
			continue
		}
		if ok, err := secrets.Verify(u.Identities[i].PasswordHash, in.Password); err == nil && ok {
			continue
		}
		h, err := secrets.Hash(in.Password)
		if err != nil {
			return err
		}
		u.Identities[i].PasswordHash = h
	}
	if create {
		return st.Users().Create(ctx, u)
	}
	return st.Users().Update(ctx, u)
}
