package seed

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/exchangerules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// maxClientCredentials is the number of credentials one client may hold.
const maxClientCredentials = 2

const maxCredentialName = 128

// ClientCredential is a public key a client authenticates or signs request
// objects with. The settings below name it by name. Alg defaults to RS256 and
// kid to the key's RFC 7638 thumbprint.
type ClientCredential struct {
	Name string `yaml:"name"`
	Pem  string `yaml:"pem"`
	Alg  string `yaml:"alg"`
	Kid  string `yaml:"kid"`
}

// ClientAuthenticationMethods is Auth0's client_authentication_methods; the
// seed refers to its credentials by name.
type ClientAuthenticationMethods struct {
	PrivateKeyJWT *CredentialRefs `yaml:"private_key_jwt"`
}

// CredentialRefs lists credentials of the same client by name.
type CredentialRefs struct {
	Credentials []string `yaml:"credentials"`
}

// SignedRequestObject is Auth0's signed_request_object client setting.
type SignedRequestObject struct {
	Required    bool     `yaml:"required"`
	Credentials []string `yaml:"credentials"`
}

// ClientTokenExchange is Auth0's token_exchange client setting.
type ClientTokenExchange struct {
	AllowAnyProfileOfType []string `yaml:"allow_any_profile_of_type"`
}

// TokenExchangeProfile binds a subject_token_type to a custom token exchange
// Action, named here by its name. The profile is identified by its
// subject_token_type.
type TokenExchangeProfile struct {
	Name             string `yaml:"name"`
	Type             string `yaml:"type"`
	SubjectTokenType string `yaml:"subject_token_type"`
	Action           string `yaml:"action"`
}

// parsedCredential is a seeded credential after validation.
type parsedCredential struct {
	name, kid, alg, thumbprint string
	der                        []byte
}

func (c *Client) usesPrivateKeyJWT() bool {
	return c.ClientAuthenticationMethods != nil && c.ClientAuthenticationMethods.PrivateKeyJWT != nil
}

// usesCredentialStorage reports whether the client writes anything that only
// a store with client_credentials.v1 keeps.
func (c *Client) usesCredentialStorage() bool {
	return len(c.Credentials) > 0 || c.usesPrivateKeyJWT() || c.SignedRequestObject != nil || c.TokenExchange != nil
}

// validateCredentials parses the client's credentials and checks the settings
// that name them. It runs before the client's spec is built.
func (c *Client) validateCredentials() []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("client %q: "+format, append([]any{c.ClientID}, args...)...))
	}
	c.parsedCredentials = nil
	if len(c.Credentials) > maxClientCredentials {
		fail("credentials: at most %d credentials", maxClientCredentials)
	}
	names, kids := map[string]bool{}, map[string]bool{}
	for i, in := range c.Credentials {
		switch {
		case in.Name == "":
			fail("credentials[%d]: name is required", i)
			continue
		case utf8.RuneCountInString(in.Name) > maxCredentialName:
			fail("credentials[%d]: name must be at most %d characters", i, maxCredentialName)
			continue
		case names[in.Name]:
			fail("credentials: duplicate name %q", in.Name)
			continue
		case in.Pem == "":
			fail("credentials %q: pem is required", in.Name)
			continue
		case in.Kid != "" && !clientcred.KIDPattern.MatchString(in.Kid):
			fail("credentials %q: kid must match %s", in.Name, clientcred.KIDPattern)
			continue
		}
		names[in.Name] = true
		alg := in.Alg
		if alg == "" {
			alg = "RS256"
		}
		parsed, err := clientcred.ParsePEM("public_key", in.Pem, alg)
		if err != nil {
			fail("credentials %q: %v", in.Name, err)
			continue
		}
		kid := in.Kid
		if kid == "" {
			kid = parsed.KID
		}
		if kids[kid] {
			fail("credentials: duplicate kid %q", kid)
			continue
		}
		kids[kid] = true
		c.parsedCredentials = append(c.parsedCredentials, parsedCredential{name: in.Name, kid: kid, alg: alg, thumbprint: parsed.Thumbprint, der: parsed.DER})
	}
	refs := func(setting string, list []string) {
		seen := map[string]bool{}
		for _, name := range list {
			switch {
			case !names[name]:
				fail("%s: credential %q is not defined in credentials", setting, name)
			case seen[name]:
				fail("%s: credential %q is listed twice", setting, name)
			}
			seen[name] = true
		}
	}
	if c.usesPrivateKeyJWT() {
		if c.TokenEndpointAuthMethod != "" {
			fail("token_endpoint_auth_method must be omitted while client_authentication_methods.private_key_jwt is set")
		}
		refs("client_authentication_methods.private_key_jwt", c.ClientAuthenticationMethods.PrivateKeyJWT.Credentials)
	}
	if c.SignedRequestObject != nil {
		refs("signed_request_object", c.SignedRequestObject.Credentials)
	}
	if c.TokenExchange != nil {
		for _, t := range c.TokenExchange.AllowAnyProfileOfType {
			if t != exchangerules.TypeCustomAuthentication {
				fail("token_exchange.allow_any_profile_of_type may only contain %s", exchangerules.TypeCustomAuthentication)
			}
		}
	}
	return errs
}

// credentialIDs maps credential names to the ids of the stored credentials.
func credentialIDs(byName map[string]string, names []string) []string {
	ids := make([]string, 0, len(names))
	for _, n := range names {
		ids = append(ids, byName[n])
	}
	return ids
}

// applyClientCredentials makes the client's stored credentials match the
// seed's and attaches them to the private_key_jwt and signed_request_object
// settings. A client whose seed has no credentials key keeps its stored
// credentials; one with a credentials list keeps exactly those keys: a key
// is the same when its kid, algorithm, name and public key match, any other
// stored key is deleted, and a missing one is created.
func applyClientCredentials(ctx context.Context, st store.Store, tenantID string, in Client, now time.Time) error {
	byName := map[string]string{}
	if in.Credentials != nil {
		stored, err := st.ClientCredentials().List(ctx, tenantID, in.ClientID)
		if err != nil {
			return err
		}
		matched := map[string]bool{}
		var drop []*store.ClientCredential
		for _, s := range stored {
			i := slices.IndexFunc(in.parsedCredentials, func(p parsedCredential) bool {
				return p.kid == s.KID && p.alg == s.Alg && p.name == s.Name && string(p.der) == string(s.PublicKeyDER) && !matched[p.name]
			})
			if i < 0 {
				drop = append(drop, s)
				continue
			}
			matched[in.parsedCredentials[i].name] = true
			byName[in.parsedCredentials[i].name] = s.ID
		}
		// Delete before creating: a client holds at most two keys.
		for _, s := range drop {
			if err := st.ClientCredentials().Delete(ctx, tenantID, in.ClientID, s.ID); err != nil {
				return err
			}
		}
		for _, p := range in.parsedCredentials {
			if matched[p.name] {
				continue
			}
			cred := &store.ClientCredential{
				TenantID: tenantID, ClientID: in.ClientID, ID: "cred_" + secrets.RandomString(22), Type: "public_key",
				Name: p.name, KID: p.kid, Alg: p.alg, PublicKeyDER: p.der, Thumbprint: p.thumbprint, CreatedAt: now, UpdatedAt: now,
			}
			if err := st.ClientCredentials().Create(ctx, cred, maxClientCredentials); err != nil {
				return fmt.Errorf("credential %q: %w", p.name, err)
			}
			byName[p.name] = cred.ID
		}
	}
	if !in.usesPrivateKeyJWT() && in.SignedRequestObject == nil {
		return nil
	}
	c, err := st.Clients().Get(ctx, tenantID, in.ClientID)
	if err != nil {
		return err
	}
	if in.usesPrivateKeyJWT() {
		c.PrivateKeyJWTCredentials = credentialIDs(byName, in.ClientAuthenticationMethods.PrivateKeyJWT.Credentials)
	}
	if so := in.SignedRequestObject; so != nil {
		c.SignedRequestObject = &store.SignedRequestObject{Required: so.Required, Credentials: credentialIDs(byName, so.Credentials)}
	}
	return st.Clients().Update(ctx, c)
}

// setClientCredentialSettings sets the settings that need no stored
// credential. The attachments are written by applyClientCredentials once the
// credentials exist.
func setClientCredentialSettings(c *store.Client, in Client) {
	c.PrivateKeyJWTCredentials, c.SignedRequestObject, c.TokenExchangeTypes = nil, nil, nil
	if in.usesPrivateKeyJWT() {
		c.TokenEndpointAuthMethod = ""
	}
	if in.TokenExchange != nil {
		c.TokenExchangeTypes = slices.Clone(in.TokenExchange.AllowAnyProfileOfType)
		if c.TokenExchangeTypes == nil {
			c.TokenExchangeTypes = []string{}
		}
	}
}

// setSigningSecret finishes an HS256 API: the seed's secret when it names
// one (kept when it already matches), otherwise the stored secret, otherwise
// a generated one. Re-applying a seed never rotates a secret it does not
// name.
func setSigningSecret(w keys.Wrapper, rs *store.ResourceServer, secret string) error {
	if secret == "" {
		if len(rs.SigningSecretSealed) > 0 {
			return nil
		}
		var err error
		if secret, err = keys.NewAPISigningSecret(); err != nil {
			return err
		}
	} else if len(rs.SigningSecretSealed) > 0 {
		if got, err := keys.OpenAPISigningSecret(w, rs.TenantID, rs.ID, rs.SigningSecretSealed); err == nil && string(got) == secret {
			return nil
		}
	}
	sealed, err := keys.SealAPISigningSecret(w, rs.TenantID, rs.ID, secret)
	if err != nil {
		return err
	}
	rs.SigningSecretSealed = sealed
	return nil
}

// validateSigning checks the signing fields of a seeded API.
func validateSigning(rs *ResourceServer, alg string) []error {
	var errs []error
	if rs.SigningSecret == "" {
		return nil
	}
	if alg != apirules.SigningAlgHS256 {
		errs = append(errs, errors.New("signing_secret is only valid with signing_alg HS256"))
	} else if utf8.RuneCountInString(rs.SigningSecret) < apirules.MinSigningSecretLength {
		errs = append(errs, fmt.Errorf("signing_secret must be at least %d characters", apirules.MinSigningSecretLength))
	}
	return errs
}

// usesClientCredentials reports seeded data that only a store with
// client_credentials.v1 keeps.
func usesClientCredentials(f *File) bool {
	for _, t := range f.Tenants {
		if len(t.TokenExchangeProfiles) > 0 {
			return true
		}
		for _, rs := range t.ResourceServers {
			if rs.normalized != nil && rs.normalized.SigningAlg == apirules.SigningAlgHS256 {
				return true
			}
		}
		for i := range t.Clients {
			if t.Clients[i].usesCredentialStorage() {
				return true
			}
		}
	}
	return false
}

// checkClientCredentialsStorage refuses that data on a store without the
// capability, before anything is written, rather than half-applying it.
func checkClientCredentialsStorage(ctx context.Context, st store.Store, f *File) error {
	if !usesClientCredentials(f) || store.ClientCredentialsAvailable(ctx, st) {
		return nil
	}
	return fmt.Errorf("seed: client credentials, token exchange profiles and HS256 API signing need a store plugin with client_credentials.v1: %w", store.ErrClientCredentialsUnavailable)
}

func hasProfiles(f *File) bool {
	for _, t := range f.Tenants {
		if len(t.TokenExchangeProfiles) > 0 {
			return true
		}
	}
	return false
}

// validateTokenExchangeProfiles checks the profiles with the Management API's
// rules, and the seeded Actions they name.
func validateTokenExchangeProfiles(t *Tenant) []error {
	var errs []error
	types := map[string]bool{}
	for i, p := range t.TokenExchangeProfiles {
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("token_exchange_profiles[%d]: "+format, append([]any{i}, args...)...))
		}
		if p.Type != "" && p.Type != exchangerules.TypeCustomAuthentication {
			fail("type must be %s", exchangerules.TypeCustomAuthentication)
		}
		if err := exchangerules.ValidateName(p.Name); err != nil {
			fail("%v", err)
		}
		if err := exchangerules.ValidateSubjectTokenType(p.SubjectTokenType); err != nil {
			fail("%v", err)
		}
		if types[p.SubjectTokenType] {
			fail("duplicate subject_token_type %q", p.SubjectTokenType)
		}
		types[p.SubjectTokenType] = true
		if p.Action == "" {
			fail("action is required")
			continue
		}
		if j := slices.IndexFunc(t.Actions, func(a Action) bool { return a.Name == p.Action }); j >= 0 {
			if err := profileAction(t.Actions[j].SupportedTriggers, t.Actions[j].Deploy); err != nil {
				fail("Action %q: %v", p.Action, err)
			}
		}
	}
	if len(t.TokenExchangeProfiles) > exchangerules.MaxProfiles {
		errs = append(errs, fmt.Errorf("token_exchange_profiles: at most %d profiles", exchangerules.MaxProfiles))
	}
	return errs
}

func profileAction(triggers []ActionTrigger, deploy bool) error {
	if len(triggers) != 1 || triggers[0].ID != actions.TriggerCustomTokenExchange {
		return fmt.Errorf("must have supported_triggers custom-token-exchange")
	}
	if !deploy {
		return errors.New("must be deployed (deploy: true)")
	}
	return nil
}

// applyTokenExchangeProfiles creates the profiles the store lacks, matching
// by subject_token_type. In ModeApply an existing profile takes the seed's
// name and Action; in create-only mode it is left alone.
func applyTokenExchangeProfiles(ctx context.Context, st store.Store, tenantID string, in []TokenExchangeProfile, now time.Time, createOnly bool) error {
	for _, p := range in {
		existing, err := st.ClientCredentials().GetProfileByType(ctx, tenantID, p.SubjectTokenType)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil && createOnly {
			continue
		}
		a, err2 := st.Actions().GetActionByName(ctx, tenantID, p.Action)
		switch {
		case errors.Is(err2, store.ErrNotFound):
			return fmt.Errorf("token exchange profile %q: Action %q does not exist", p.Name, p.Action)
		case err2 != nil:
			return err2
		}
		if profileErr := profileAction([]ActionTrigger{{ID: a.Trigger}}, a.DeployedVersionID != ""); profileErr != nil {
			return fmt.Errorf("token exchange profile %q: Action %q: %w", p.Name, p.Action, profileErr)
		}
		if existing == nil {
			err = st.ClientCredentials().CreateProfile(ctx, &store.TokenExchangeProfile{
				TenantID: tenantID, ID: "tep_" + secrets.RandomString(22), Name: p.Name, SubjectTokenType: p.SubjectTokenType,
				ActionID: a.ID, Type: exchangerules.TypeCustomAuthentication, CreatedAt: now, UpdatedAt: now,
			}, exchangerules.MaxProfiles)
		} else if existing.Name != p.Name || existing.ActionID != a.ID {
			next := *existing
			next.Name, next.ActionID, next.UpdatedAt = p.Name, a.ID, now
			err = st.ClientCredentials().UpdateProfile(ctx, &next)
		}
		if err != nil {
			return fmt.Errorf("token exchange profile %q: %w", p.Name, err)
		}
	}
	return nil
}
