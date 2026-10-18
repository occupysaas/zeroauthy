// Package apirules holds the rules every API (resource server) must follow,
// whoever writes it: the seed and the Management API. Spec is an API's
// settings in Auth0's terms; Normalize fills in the defaults and validates;
// Apply copies a Spec into a store.ResourceServer and FromResourceServer
// reads one back. internal/clientrules does the same for applications.
package apirules

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Limits and defaults (D-0041).
const (
	MaxIdentifier       = 600
	MaxName             = 200
	MaxScopeValue       = 280
	MaxScopeDescription = 500
	// MaxTokenLifetime is 30 days, in seconds.
	MaxTokenLifetime = 2592000

	// The lifetimes an API reports when it sets none.
	DefaultTokenLifetime       = 86400
	DefaultTokenLifetimeForWeb = 7200

	// SigningAlg is the only algorithm zeroauthy signs access tokens with.
	SigningAlg = "RS256"
)

// Spec is an API's settings. Empty strings, zeros and nil pointers mean
// "the default", which Normalize fills in or the token endpoint applies.
type Spec struct {
	Identifier string
	// Name is optional; an empty name is an API without one.
	Name   string
	Scopes []store.Scope
	// TokenLifetime and TokenLifetimeForWeb are in seconds; zero means the
	// default.
	TokenLifetime       int
	TokenLifetimeForWeb int
	// CheckWebLifetime is set when the caller sent token_lifetime_for_web:
	// Normalize then requires it not to exceed the token lifetime. A stored
	// web lifetime above a lowered token_lifetime is not an error (D-0041).
	CheckWebLifetime   bool
	AllowOfflineAccess bool

	SkipConsentForVerifiableFirstPartyClients *bool
	SubjectTypeAuthorization                  store.SubjectTypeAuthorization
}

// Reserved reports why identifier cannot name an API: urn:zeroauthy:management
// belongs to the system tenant's operator tokens, and mgmtAPI (the tenant's
// Management API identifier, empty when the tenant has none) to the tenant's
// own Management API.
func Reserved(identifier, mgmtAPI string) error {
	switch {
	case identifier == tenant.OperatorAudience:
		return fmt.Errorf("identifier %q is reserved for zeroauthy's system tenant", identifier)
	case mgmtAPI != "" && identifier == mgmtAPI:
		return fmt.Errorf("identifier %q is reserved for the tenant's Management API", identifier)
	}
	return nil
}

// Normalize fills in s's defaults and reports everything wrong with it. It
// does not check Reserved: the system APIs have reserved identifiers, and
// callers that create an API check it.
func Normalize(s *Spec) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if n := utf8.RuneCountInString(s.Identifier); n < 1 || n > MaxIdentifier {
		fail("identifier must be 1 to %d characters", MaxIdentifier)
	}
	if utf8.RuneCountInString(s.Name) > MaxName {
		fail("name must be at most %d characters", MaxName)
	}
	if strings.ContainsAny(s.Name, "<>") {
		fail("name must not contain < or >")
	}
	seen := map[string]bool{}
	for _, sc := range s.Scopes {
		if n := utf8.RuneCountInString(sc.Value); n < 1 || n > MaxScopeValue {
			fail("scope value %q must be 1 to %d characters", sc.Value, MaxScopeValue)
		}
		if utf8.RuneCountInString(sc.Description) > MaxScopeDescription {
			fail("scope %q: description must be at most %d characters", sc.Value, MaxScopeDescription)
		}
		if seen[sc.Value] {
			fail("duplicate scope %q", sc.Value)
		}
		seen[sc.Value] = true
	}
	if s.TokenLifetime < 0 || s.TokenLifetime > MaxTokenLifetime {
		fail("token_lifetime must be 1 to %d seconds", MaxTokenLifetime)
	}
	if s.TokenLifetimeForWeb < 0 || s.TokenLifetimeForWeb > MaxTokenLifetime {
		fail("token_lifetime_for_web must be 1 to %d seconds", MaxTokenLifetime)
	}
	if s.CheckWebLifetime && s.TokenLifetimeForWeb > cmp.Or(s.TokenLifetime, DefaultTokenLifetime) {
		fail("token_lifetime_for_web must not exceed token_lifetime")
	}

	if s.SkipConsentForVerifiableFirstPartyClients == nil {
		skip := false // O1a: Auth0's default for new APIs (D-0026)
		s.SkipConsentForVerifiableFirstPartyClients = &skip
	}
	sta := &s.SubjectTypeAuthorization
	if sta.User == "" {
		sta.User = store.PolicyAllowAll
	}
	if sta.Client == "" {
		sta.Client = store.PolicyRequireClientGrant
	}
	if !slices.Contains([]string{store.PolicyAllowAll, store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.User) {
		fail("subject_type_authorization.user.policy %q must be allow_all, require_client_grant or deny_all", sta.User)
	}
	if !slices.Contains([]string{store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.Client) {
		fail("subject_type_authorization.client.policy %q must be require_client_grant or deny_all", sta.Client)
	}
	return errs
}

// Apply copies a normalized s into rs. It leaves the identity (tenant, ID,
// identifier, creation time, is_system and origin) alone.
func Apply(rs *store.ResourceServer, s *Spec) {
	rs.Name = s.Name
	rs.Scopes = slices.Clone(s.Scopes)
	rs.SigningAlg = SigningAlg
	rs.TokenLifetime, rs.TokenLifetimeForWeb = s.TokenLifetime, s.TokenLifetimeForWeb
	rs.AllowOfflineAccess = s.AllowOfflineAccess
	rs.SkipConsentForVerifiableFirstPartyClients = *s.SkipConsentForVerifiableFirstPartyClients
	rs.SubjectTypeAuthorization = s.SubjectTypeAuthorization
}

// FromResourceServer returns rs's settings as a normalized Spec, the
// starting point of an update.
func FromResourceServer(rs *store.ResourceServer) Spec {
	skip := rs.SkipConsentForVerifiableFirstPartyClients
	return Spec{
		Identifier: rs.Identifier, Name: rs.Name, Scopes: slices.Clone(rs.Scopes),
		TokenLifetime: rs.TokenLifetime, TokenLifetimeForWeb: rs.TokenLifetimeForWeb,
		AllowOfflineAccess:                        rs.AllowOfflineAccess,
		SkipConsentForVerifiableFirstPartyClients: &skip,
		SubjectTypeAuthorization:                  rs.SubjectTypeAuthorization,
	}
}
