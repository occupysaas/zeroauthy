package deploymigration

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type BootstrapResult struct {
	TenantID       string
	ClientCount    int
	AlreadyApplied bool
}
type BootstrapOptions struct{ ExcludedClientIDs []string }

type exportedClient struct {
	ClientID               string               `json:"client_id"`
	Name                   string               `json:"name"`
	AppType                string               `json:"app_type"`
	AuthMethod             string               `json:"token_endpoint_auth_method"`
	GrantTypes             []string             `json:"grant_types"`
	Callbacks              []string             `json:"callbacks"`
	AllowedLogoutURLs      []string             `json:"allowed_logout_urls"`
	WebOrigins             []string             `json:"web_origins"`
	AllowedOrigins         []string             `json:"allowed_origins"`
	IDTokenLifetime        int                  `json:"id_token_lifetime"`
	IsFirstParty           *bool                `json:"is_first_party"`
	ThirdPartySecurityMode string               `json:"third_party_security_mode"`
	RedirectionPolicy      string               `json:"redirection_policy"`
	RefreshToken           exportedRefreshToken `json:"refresh_token"`
	Tenant                 string               `json:"tenant"`
	CreatedAt              string               `json:"created_at"`
	UpdatedAt              string               `json:"updated_at"`
	OIDCConformant         *bool                `json:"oidc_conformant"`
	JWTConfiguration       struct {
		Alg           string `json:"alg"`
		Lifetime      int    `json:"lifetime_in_seconds"`
		SecretEncoded bool   `json:"secret_encoded"`
	} `json:"jwt_configuration"`
	SkipConfirmation *bool `json:"skip_non_verifiable_callback_uri_confirmation_prompt"`
	RequirePAR       bool  `json:"require_pushed_authorization_requests"`

	OrganizationUsage            string   `json:"organization_usage"`
	OrganizationRequireBehavior  string   `json:"organization_require_behavior"`
	OrganizationDiscoveryMethods []string `json:"organization_discovery_methods"`
}

type exportedRefreshToken struct {
	RotationType              string `json:"rotation_type"`
	ExpirationType            string `json:"expiration_type"`
	Leeway                    int    `json:"leeway"`
	TokenLifetime             int    `json:"token_lifetime"`
	IdleTokenLifetime         int    `json:"idle_token_lifetime"`
	InfiniteTokenLifetime     bool   `json:"infinite_token_lifetime"`
	InfiniteIdleTokenLifetime bool   `json:"infinite_idle_token_lifetime"`
}

// PrepareBootstrap combines a destination's local create-only bootstrap with
// source application identity/auth data and credentials from a protected file.
func PrepareBootstrap(source Export, bootstrap *seed.File, credentials map[string]string, opts BootstrapOptions) (*seed.File, error) {
	if err := ValidateOrganizations(source); err != nil {
		return nil, err
	}
	if bootstrap == nil || len(bootstrap.Tenants) != 1 || bootstrap.Tenants[0].Name == "" || len(bootstrap.Tenants[0].Domains) == 0 {
		return nil, errors.New("deploymigration: bootstrap seed must describe exactly one tenant with local domains")
	}
	out, err := cloneSeed(bootstrap)
	if err != nil {
		return nil, err
	}
	t := &out.Tenants[0]
	if t.Name == "system" {
		return nil, errors.New("deploymigration: destination cannot be the reserved system tenant")
	}
	clientsRaw := source.Resources["clients"]
	var rows []json.RawMessage
	if len(clientsRaw) > 0 {
		if err := json.Unmarshal(clientsRaw, &rows); err != nil {
			return nil, errors.New("deploymigration: source clients must be an array")
		}
	}
	excluded := map[string]bool{}
	for _, id := range opts.ExcludedClientIDs {
		if strings.TrimSpace(id) == "" || excluded[id] {
			return nil, errors.New("deploymigration: invalid duplicate client exclusion")
		}
		excluded[id] = true
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, c := range t.Clients {
		seenID[c.ClientID], seenName[c.Name] = true, true
	}
	neededSecrets := map[string]bool{}
	for _, raw := range rows {
		var c exportedClient
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, errors.New("deploymigration: source client contains unsupported fields")
		}
		if c.ClientID == "" || c.Name == "" || c.AppType == "" || seenID[c.ClientID] || seenName[c.Name] {
			return nil, errors.New("deploymigration: source client IDs and names must be unique and nonempty")
		}
		if excluded[c.ClientID] {
			continue
		}
		seenID[c.ClientID], seenName[c.Name] = true, true
		if (c.OIDCConformant != nil && !*c.OIDCConformant) || (c.JWTConfiguration.Alg != "" && c.JWTConfiguration.Alg != "RS256") || c.JWTConfiguration.SecretEncoded {
			return nil, errors.New("deploymigration: source client has unsupported token settings")
		}
		if c.JWTConfiguration.Lifetime != 0 {
			if c.IDTokenLifetime != 0 && c.IDTokenLifetime != c.JWTConfiguration.Lifetime {
				return nil, errors.New("deploymigration: conflicting ID-token lifetimes")
			}
			c.IDTokenLifetime = c.JWTConfiguration.Lifetime
		}
		pub := c.AuthMethod == store.AuthMethodNone
		secret := credentials[c.ClientID]
		if pub && secret != "" {
			return nil, errors.New("deploymigration: credentials supplied for a public client")
		}
		if !pub {
			if secret == "" {
				return nil, errors.New("deploymigration: a confidential source client is missing a credential")
			}
			neededSecrets[c.ClientID] = true
		}
		t.Clients = append(t.Clients, seed.Client{
			OrganizationUsage: c.OrganizationUsage, OrganizationRequireBehavior: c.OrganizationRequireBehavior, OrganizationDiscoveryMethods: slices.Clone(c.OrganizationDiscoveryMethods),
			ClientID: c.ClientID, Name: c.Name, AppType: c.AppType, ClientSecret: secret,
			TokenEndpointAuthMethod: c.AuthMethod, GrantTypes: slices.Clone(c.GrantTypes), Callbacks: slices.Clone(c.Callbacks),
			AllowedLogoutURLs: slices.Clone(c.AllowedLogoutURLs), WebOrigins: slices.Clone(c.WebOrigins), AllowedOrigins: slices.Clone(c.AllowedOrigins),
			IDTokenLifetime: c.IDTokenLifetime, IsFirstParty: c.IsFirstParty, ThirdPartySecurityMode: c.ThirdPartySecurityMode,
			RedirectionPolicy: c.RedirectionPolicy, RefreshToken: seed.RefreshToken{RotationType: c.RefreshToken.RotationType, ExpirationType: c.RefreshToken.ExpirationType, Leeway: c.RefreshToken.Leeway, TokenLifetime: c.RefreshToken.TokenLifetime, IdleTokenLifetime: c.RefreshToken.IdleTokenLifetime}, SkipNonVerifiableCallbackURIConfirmationPrompt: c.SkipConfirmation, RequirePushedAuthorizationRequests: c.RequirePAR})
	}
	for id, secret := range credentials {
		if secret == "" || (!neededSecrets[id] && !excluded[id]) {
			return nil, errors.New("deploymigration: credential file contains an unknown or public client ID")
		}
	}
	out.Mode = seed.ModeCreateOnly
	// Round-trip through the strict seed parser so every merged client follows
	// the existing shared validation and immutable-property rules.
	if err := seed.ValidateFile(out); err != nil {
		return nil, errors.New("deploymigration: prepared bootstrap failed seed validation")
	}
	return out, nil
}

func cloneSeed(f *seed.File) (*seed.File, error) {
	if f == nil {
		return nil, errors.New("deploymigration: invalid bootstrap seed")
	}
	out := *f
	out.Tenants = slices.Clone(f.Tenants)
	for i := range out.Tenants {
		out.Tenants[i].Clients = slices.Clone(f.Tenants[i].Clients)
	}
	return &out, nil
}

// CheckExportInventory fails closed if the deploy tool would omit a user API
// merely because it has the reserved built-in name.
func CheckExportInventory(resourceServers []json.RawMessage) error {
	for _, raw := range resourceServers {
		var rs struct {
			Name     string `json:"name"`
			IsSystem bool   `json:"is_system"`
		}
		if err := json.Unmarshal(raw, &rs); err != nil {
			return errors.New("deploymigration: invalid resource-server inventory")
		}
		if rs.Name == "Auth0 Management API" && !rs.IsSystem {
			return errors.New("deploymigration: a user API collides with the deploy tool's excluded system API name")
		}
	}
	return nil
}

// CheckBootstrap performs a read-only fresh-or-matching-bootstrap check.
func CheckBootstrap(ctx context.Context, st store.Store, f *seed.File, w keys.Wrapper) (BootstrapResult, error) {
	if err := validateBootstrap(f, w); err != nil {
		return BootstrapResult{}, err
	}
	t := f.Tenants[0]
	result := BootstrapResult{ClientCount: len(t.Clients)}
	existing, err := st.Tenants().GetByName(ctx, t.Name)
	if errors.Is(err, store.ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return BootstrapResult{}, errors.New("deploymigration: cannot inspect destination tenant")
	}
	if existing.Reserved || existing.Origin == store.OriginAPI || !reflect.DeepEqual(normalizedHosts(existing.Domains), normalizedHosts(t.Domains)) {
		return BootstrapResult{}, errors.New("deploymigration: destination tenant conflicts with bootstrap identity")
	}
	result.TenantID, result.AlreadyApplied = existing.ID, true
	for _, in := range t.Clients {
		current, err := st.Clients().Get(ctx, existing.ID, in.ClientID)
		if errors.Is(err, store.ErrNotFound) {
			return BootstrapResult{}, errors.New("deploymigration: destination bootstrap is partial")
		}
		if err != nil {
			return BootstrapResult{}, errors.New("deploymigration: cannot inspect destination client")
		}
		spec := clientSpec(in, t.PushedAuthorizationRequestsSupported)
		if errs := clientrules.Normalize(&spec, t.PushedAuthorizationRequestsSupported); len(errs) > 0 {
			return BootstrapResult{}, errors.New("deploymigration: invalid bootstrap client")
		}
		if err := clientrules.CheckImmutable(current, &spec); err != nil || current.AppType != store.AppType(spec.AppType) || current.TokenEndpointAuthMethod != spec.TokenEndpointAuthMethod {
			return BootstrapResult{}, errors.New("deploymigration: destination client authentication properties conflict")
		}
		if in.TokenEndpointAuthMethod != store.AuthMethodNone {
			matched := false
			for _, secret := range current.Secrets {
				if secret.ExpiresAt != nil && !secret.ExpiresAt.After(time.Now()) {
					continue
				}
				var got string
				if len(secret.Sealed) > 0 {
					got, err = keys.OpenClientSecret(w, current.TenantID, current.ClientID, secret.Sealed)
				} else if secret.Hash != "" {
					var ok bool
					ok, err = secrets.Verify(secret.Hash, in.ClientSecret)
					if ok {
						matched = true
						break
					}
				}
				if err == nil && subtle.ConstantTimeCompare([]byte(got), []byte(in.ClientSecret)) == 1 {
					matched = true
					break
				}
			}
			if !matched {
				return BootstrapResult{}, errors.New("deploymigration: destination client credential does not match bootstrap")
			}
		}
	}
	for _, g := range t.ClientGrants {
		clientID := g.ClientID
		grant, err := st.ClientGrants().Find(ctx, existing.ID, clientID, g.Audience, g.SubjectType)
		if err != nil || !sameStringSet(grant.Scopes, g.Scopes) {
			return BootstrapResult{}, errors.New("deploymigration: destination bootstrap grant is missing or changed")
		}
	}
	return result, nil
}

func ApplyBootstrap(ctx context.Context, st store.Store, f *seed.File, w keys.Wrapper, now func() time.Time) (BootstrapResult, error) {
	if err := validateBootstrap(f, w); err != nil {
		return BootstrapResult{}, err
	}
	var result BootstrapResult
	err := st.WithTx(ctx, func(tx store.Store) error {
		check, err := CheckBootstrap(ctx, tx, f, w)
		if err != nil {
			return err
		}
		if check.AlreadyApplied {
			result = check
			return nil
		}
		ff := *f
		ff.Mode = seed.ModeCreateOnly
		if err := seed.Apply(ctx, tx, &ff, now, w); err != nil {
			return errors.New("deploymigration: bootstrap application failed; no credential values were logged")
		}
		tn, err := tx.Tenants().GetByName(ctx, f.Tenants[0].Name)
		if err != nil {
			return errors.New("deploymigration: created tenant cannot be inspected")
		}
		result = BootstrapResult{TenantID: tn.ID, ClientCount: len(f.Tenants[0].Clients)}
		return nil
	})
	if err != nil {
		return BootstrapResult{}, err
	}
	return result, nil
}

func validateBootstrap(f *seed.File, w keys.Wrapper) error {
	if f == nil || len(f.Tenants) != 1 || f.Tenants[0].Name == "" || f.Tenants[0].Name == "system" || len(f.Tenants[0].Domains) == 0 || w == nil {
		return errors.New("deploymigration: bootstrap requires one ordinary tenant, domains and a master-key wrapper")
	}
	for _, c := range f.Tenants[0].Clients {
		if c.ClientID == "" {
			return errors.New("deploymigration: bootstrap client is missing its ID")
		}
	}
	return nil
}

func clientSpec(c seed.Client, parSupported bool) clientrules.Spec {
	return clientrules.Spec{
		OrganizationUsage: c.OrganizationUsage, OrganizationRequireBehavior: c.OrganizationRequireBehavior, OrganizationDiscoveryMethods: slices.Clone(c.OrganizationDiscoveryMethods),
		Name: c.Name, AppType: c.AppType, TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, GrantTypes: slices.Clone(c.GrantTypes), Callbacks: slices.Clone(c.Callbacks), AllowedLogoutURLs: slices.Clone(c.AllowedLogoutURLs), WebOrigins: slices.Clone(c.WebOrigins), AllowedOrigins: slices.Clone(c.AllowedOrigins), IDTokenLifetime: c.IDTokenLifetime, IsFirstParty: c.IsFirstParty, ThirdPartySecurityMode: c.ThirdPartySecurityMode, RedirectionPolicy: c.RedirectionPolicy, RefreshToken: clientrules.RefreshToken{RotationType: c.RefreshToken.RotationType, ExpirationType: c.RefreshToken.ExpirationType, Leeway: c.RefreshToken.Leeway, TokenLifetime: c.RefreshToken.TokenLifetime, IdleTokenLifetime: c.RefreshToken.IdleTokenLifetime}, RequirePushedAuthorizationRequests: c.RequirePushedAuthorizationRequests}
}
func normalizedHosts(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = tenant.NormalizeHost(v)
	}
	slices.Sort(out)
	return out
}
func sameStringSet(a, b []string) bool {
	aa, bb := slices.Clone(a), slices.Clone(b)
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}
