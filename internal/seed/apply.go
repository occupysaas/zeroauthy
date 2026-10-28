package seed

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// Apply upserts everything in f. It never deletes. With f.Mode set to
// ModeCreateOnly it only creates what does not exist yet and leaves every
// existing entity as it is, so edits made in the console survive a restart.
//
// A transaction that fails with store.ErrConflict is retried once: two
// replicas seeding a fresh shared database both see a tenant (or client, or
// user) as missing, and the loser's insert conflicts. On the retry the
// winner's rows exist and are updated instead.
func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper) error {
	if hasActions(f) {
		return errors.New("seed: Actions require ApplyWithActions")
	}
	return applyOrdinary(ctx, st, f, now, w)
}

func applyOrdinary(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper) error {
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
	if !f.mgmtChecked {
		for _, t := range f.Tenants {
			if len(t.mgmtAudiences) > 0 {
				return fmt.Errorf("seed: tenant %q: client grants for the Management API need the server's base domain (File.CheckManagementAPI)", t.Name)
			}
		}
	}
	return st.WithTx(ctx, func(tx store.Store) error {
		for _, t := range f.Tenants {
			if err := applyTenant(ctx, tx, f, t, now().UTC(), w); err != nil {
				return fmt.Errorf("seed: tenant %q: %w", t.Name, err)
			}
		}
		return nil
	})
}

func applyTenant(ctx context.Context, st store.Store, f *File, in Tenant, now time.Time, w keys.Wrapper) error {
	createOnly := f.Mode == ModeCreateOnly
	existing, err := st.Tenants().GetByName(ctx, in.Name)
	if err == nil && existing.Origin == store.OriginAPI {
		// Created through the system API: the seed never touches it.
		return nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	exists := err == nil
	domains := make([]string, len(in.Domains))
	for i, d := range in.Domains {
		var err error
		domains[i], err = hostname.NormalizeOperatorHost(d)
		if err != nil {
			return fmt.Errorf("operator alias %q: %w", d, store.ErrInvalid)
		}
	}
	// Validate the old identity before applying configuration can hide drift.
	if exists {
		if err := tenantsetup.InitializeCanonical(existing, f.baseDomain); err != nil {
			return err
		}
		if err := tenantsetup.ValidateManagementAPIIdentity(ctx, st, existing, f.baseDomain); err != nil {
			return err
		}
	}
	var tn *store.Tenant
	if createOnly && exists {
		tn = existing
		if tn.Seeded {
			// The seed no longer overwrites this tenant, so the console must
			// not warn that it does. Only the marker changes.
			tn.Seeded = false
			if err := st.Tenants().Update(ctx, tn); err != nil {
				return err
			}
		}
	} else {
		tn, err = tenantsetup.UpsertTenant(ctx, st, in.Name, now, func(tn *store.Tenant) error {
			before := tn.Clone()
			tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
			tn.AllowedLogoutURLs = slices.Clone(in.AllowedLogoutURLs)
			tn.EnabledLocales = slices.Clone(in.EnabledLocales)
			tn.CustomText = in.CustomText.Clone()
			tn.SessionLifetime, tn.IdleSessionLifetime = in.SessionLifetime, in.IdleSessionLifetime
			tn.Branding = store.Branding{LogoURL: in.Branding.LogoURL, PrimaryColor: strings.ToLower(in.Branding.PrimaryColor)}
			tn.DefaultDirectory = in.DefaultDirectory
			tn.SkipNonVerifiableCallbackURIConfirmationPrompt = in.SkipNonVerifiableCallbackURIConfirmationPrompt
			tn.UseScopeDescriptionsForConsent = in.UseScopeDescriptionsForConsent
			tn.PushedAuthorizationRequestsSupported = in.PushedAuthorizationRequestsSupported
			tn.DeviceFlowCharset, tn.DeviceFlowMask = in.DeviceFlow.Charset, in.DeviceFlow.Mask
			if exists {
				preserveOmittedTenant(tn, before, in.supplied)
			}
			if exists {
				tn.CanonicalHost = existing.CanonicalHost
			}
			if err := tenantsetup.InitializeCanonical(tn, f.baseDomain); err != nil {
				return err
			}
			// A base-domain canonical is an implicit identity, not a required
			// entry in existing operator configuration.
			if f.baseDomain == "" && tn.CanonicalHost != "" && !slices.Contains(tn.Domains, tn.CanonicalHost) {
				return fmt.Errorf("cannot remove canonical host %q: %w", tn.CanonicalHost, store.ErrConflict)
			}
			if err := applyTenantSettings(tn, in, w); err != nil {
				return err
			}
			// In create-only mode nothing is overwritten later, so there is
			// nothing to warn about.
			tn.Seeded = !createOnly
			return nil
		})
		if err != nil {
			return err
		}
		if _, supplied := in.supplied["domains"]; supplied || in.supplied == nil || !exists {
			aliases := slices.Clone(tn.Domains)
			if f.baseDomain != "" && !slices.Contains(aliases, tn.CanonicalHost) {
				aliases = append(aliases, tn.CanonicalHost)
			}
			if err := customdomain.ReconcileOperatorAliases(ctx, st, tn.ID, aliases); err != nil {
				return err
			}
		}
		tn, err = st.Tenants().Get(ctx, tn.ID)
		if err != nil {
			return err
		}
	}
	if !(createOnly && exists) {
		if err := applyHostedLogin(ctx, st, tn, in); err != nil {
			return fmt.Errorf("hosted login: %w", err)
		}
	}

	if f.mgmtChecked && tenant.ManagementAPIIdentifier(tn, f.baseDomain) != "" {
		if _, err := tenantsetup.ManagementAPI(ctx, st, tn, f.baseDomain, now); err != nil {
			return fmt.Errorf("management API: %w", err)
		}
	}
	for _, rs := range in.ResourceServers {
		if err := applyResourceServer(ctx, st, tn.ID, rs, now, createOnly); err != nil {
			return fmt.Errorf("resource server %q: %w", rs.Identifier, err)
		}
	}
	for _, role := range in.Roles {
		if err := applyRole(ctx, st, tn.ID, role, createOnly); err != nil {
			return fmt.Errorf("role %q: %w", role.Name, err)
		}
	}
	for _, c := range in.Clients {
		if err := applyClient(ctx, st, tn.ID, c, now, w, createOnly); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, g := range in.ClientGrants {
		if err := applyClientGrant(ctx, st, tn.ID, g, now, createOnly); err != nil {
			return fmt.Errorf("client grant %q → %q: %w", g.ClientID, g.Audience, err)
		}
	}
	for _, c := range in.Connections {
		if err := applyConnection(ctx, st, tn.ID, c, now, w, createOnly); err != nil {
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}
	}
	if _, supplied := in.Settings["default_audience"]; supplied && !(createOnly && exists) && tn.DefaultAudience != "" {
		if _, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, tn.DefaultAudience); err != nil {
			return fmt.Errorf("settings.default_audience must resolve within the tenant: %w", err)
		}
	}
	if _, supplied := in.Settings["default_directory"]; supplied && !(createOnly && exists) && tn.DefaultDirectory != "" {
		c, err := st.Connections().GetByName(ctx, tn.ID, tn.DefaultDirectory)
		if err != nil {
			return fmt.Errorf("settings.default_directory must resolve within the tenant: %w", err)
		}
		if c.Strategy != store.StrategyDatabase {
			return fmt.Errorf("settings.default_directory must be a supported database connection")
		}
	}
	for _, u := range in.Users {
		if err := applyUser(ctx, st, tn.ID, u, now, createOnly); err != nil {
			return fmt.Errorf("user %q: %w", u.Email, err)
		}
	}
	return nil
}

func applyHostedLogin(ctx context.Context, st store.Store, tn *store.Tenant, in Tenant) error {
	current, err := (hostedlogin.Service{Store: st}).Load(ctx, tn.ID)
	if err != nil {
		return err
	}
	next := current.Clone()
	branding, hasBranding := in.supplied["branding"].(map[string]any)
	if in.supplied == nil {
		hasBranding = true
		branding = map[string]any{"logo_url": in.Branding.LogoURL, "primary_color": in.Branding.PrimaryColor}
	}
	if hasBranding {
		if next.Branding == nil {
			next.Branding = map[string]any{}
		}
		if _, ok := branding["logo_url"]; ok {
			if in.Branding.LogoURL == "" {
				delete(next.Branding, "logo_url")
			} else {
				next.Branding["logo_url"] = in.Branding.LogoURL
			}
		}
		if _, ok := branding["primary_color"]; ok {
			colors, _ := next.Branding["colors"].(map[string]any)
			colors = store.CloneSettings(colors)
			if colors == nil {
				colors = map[string]any{}
			}
			if in.Branding.PrimaryColor == "" {
				delete(colors, "primary")
			} else {
				colors["primary"] = strings.ToLower(in.Branding.PrimaryColor)
			}
			if len(colors) == 0 {
				delete(next.Branding, "colors")
			} else {
				next.Branding["colors"] = colors
			}
		}
	}
	if _, ok := in.supplied["custom_text"]; ok || in.supplied == nil {
		next.CustomText = in.CustomText.Clone()
	}
	if reflect.DeepEqual(current, next) {
		return nil
	}
	if err := brandingrules.ValidateUpdate(current, next); err != nil {
		return err
	}
	return st.HostedLogins().Put(ctx, next, current.Revision)
}

func applyResourceServer(ctx context.Context, st store.Store, tenantID string, in ResourceServer, now time.Time, createOnly bool) error {
	if rs, err := st.ResourceServers().GetByIdentifier(ctx, tenantID, in.Identifier); err == nil && (createOnly || rs.Origin == store.OriginAPI) {
		// Created through the Management API, or create-only mode: the seed
		// never touches it.
		return nil
	}
	spec := in.normalized
	if spec == nil {
		return errors.New("the resource server was not validated")
	}
	return tenantsetup.UpsertResourceServer(ctx, st, tenantID, in.Identifier, now, func(rs *store.ResourceServer) error {
		apirules.Apply(rs, spec)
		return nil
	})
}

func applyClient(ctx context.Context, st store.Store, tenantID string, in Client, now time.Time, w keys.Wrapper, createOnly bool) error {
	c, err := st.Clients().Get(ctx, tenantID, in.ClientID)
	if err == nil && (createOnly || c.Origin == store.OriginAPI) {
		// Created through the Management API, or create-only mode: the seed
		// never touches it.
		return nil
	}
	return tenantsetup.UpsertClient(ctx, st, tenantID, in.ClientID, now, func(c *store.Client, create bool) error {
		return setClient(c, create, in, now, w)
	})
}

func setClient(c *store.Client, create bool, in Client, now time.Time, w keys.Wrapper) error {
	spec := in.normalized
	if spec == nil {
		return errors.New("the client was not validated")
	}
	if !create {
		if err := clientrules.CheckImmutable(c, spec); err != nil {
			return fmt.Errorf("%w; use a new client_id", err)
		}
	}
	clientrules.Apply(c, spec)

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

func applyClientGrant(ctx context.Context, st store.Store, tenantID string, in ClientGrant, now time.Time, createOnly bool) error {
	g, err := st.ClientGrants().Find(ctx, tenantID, in.ClientID, in.Audience, in.SubjectType)
	switch {
	case err == nil && (createOnly || g.Origin == store.OriginAPI):
		// Created through the Management API, or create-only mode: the seed
		// never touches it.
		return nil
	case errors.Is(err, store.ErrNotFound):
		// "cgr_" and 16 letters and digits, the shape of Auth0's grant IDs.
		return st.ClientGrants().Create(ctx, &store.ClientGrant{
			TenantID: tenantID, ID: "cgr_" + secrets.RandomString(16),
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

func applyConnection(ctx context.Context, st store.Store, tenantID string, in Connection, now time.Time, w keys.Wrapper, createOnly bool) error {
	if c, err := st.Connections().GetByName(ctx, tenantID, in.Name); err == nil && (createOnly || c.Origin == store.OriginAPI) {
		// Created through the Management API, or create-only mode: the seed
		// never touches it.
		return nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if in.normalized != nil {
		if err := federation.RequireMicrosoftConnection(ctx, st, &store.Connection{Strategy: in.normalized.Strategy}); err != nil {
			return err
		}
	}
	return tenantsetup.UpsertConnection(ctx, st, tenantID, in.Name, now, func(c *store.Connection) error {
		return setConnection(c, in, w)
	})
}

func setConnection(c *store.Connection, in Connection, w keys.Wrapper) error {
	spec := in.normalized
	if spec == nil {
		return errors.New("the connection was not validated")
	}
	var prev *store.Connection
	if len(c.FederationSecretsSealed) > 0 {
		p := *c
		prev = &p
	}
	// The seed owns the complexity half of the password options unless it
	// names password_options; fields it does not name are left alone.
	connrules.Apply(spec, c)
	// Federated: seal the provider secret (re-using the stored blob when it
	// is unchanged), keep the immutable bindings and move the revision.
	if err := federation.ApplyConnection(w, prev, spec, c); err != nil {
		return err
	}
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

func applyUser(ctx context.Context, st store.Store, tenantID string, in User, now time.Time, createOnly bool) error {
	u, err := st.Users().FindByLogin(ctx, tenantID, in.Connection, in.Email)
	if err == nil && createOnly {
		return nil
	}
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if !create {
		// A seeded user that was since linked into another user (D-0043)
		// is found through its linked identity; the entry must not
		// rewrite the primary's profile or password.
		if id := u.IdentityByLogin(in.Connection, in.Email); id != nil && id.Linked() {
			slog.WarnContext(ctx, "seed: user skipped: it is now linked into another user",
				"tenant", tenantID, "connection", in.Connection, "identity", id.Provider+"|"+id.UserID, "primary", u.UserID)
			return nil
		}
	}
	if create {
		id := secrets.RandomHex(12)
		u = &store.User{
			TenantID: tenantID, UserID: store.StrategyDatabase + "|" + id, CreatedAt: now,
			Identities: []store.Identity{{Connection: in.Connection, Provider: store.StrategyDatabase, UserID: id}},
		}
	}
	if err := federation.RequireMicrosoftUser(ctx, st, u); err != nil {
		return err
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
	conn, err := st.Connections().GetByName(ctx, tenantID, in.Connection)
	if err != nil {
		return err
	}
	password := identity.EffectivePassword(conn, in.Password)
	var newHash string
	for i := range u.Identities {
		// Only the user's own identity: a linked one keeps its password.
		if u.Identities[i].Connection != in.Connection || u.Identities[i].Linked() {
			continue
		}
		if ok, err := secrets.Verify(u.Identities[i].PasswordHash, password); err == nil && ok {
			continue
		}
		h, err := secrets.Hash(password)
		if err != nil {
			return err
		}
		u.Identities[i].PasswordHash = h
		u.Identities[i].ImportedHash = "" // at most one of the two is set
		newHash = h
	}
	if create {
		err = st.Users().Create(ctx, u)
	} else {
		err = st.Users().Update(ctx, u)
	}
	if err != nil || newHash == "" {
		return err
	}
	// A password the seed sets counts as the user's newest.
	return identity.RecordPassword(ctx, st, conn, u.UserID, newHash)
}
