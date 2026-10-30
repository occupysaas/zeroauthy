// Package orgrules validates organization inputs shared by all writers and
// holds the frozen limits (inventory.json, D-0055).
package orgrules

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// IDPrefix starts every organization ID.
const IDPrefix = "org_"

// Third-party client access values.
const (
	ThirdPartyBlock = "block"
	ThirdPartyAllow = "allow"
)

var (
	nameRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	metaKeyRE  = regexp.MustCompile(`^[a-zA-Z0-9]\w*$`)
	hexColorRE = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	idRE       *regexp.Regexp
	idOnce     sync.Once
)

var (
	limitsOnce sync.Once
	limits     map[string]int
)

// Limit returns the frozen inventory limit with the given name.
func Limit(name string) int {
	limitsOnce.Do(func() {
		limits = map[string]int{}
		for _, l := range InventoryMetadata().Limits {
			limits[l.Name] = l.Value
		}
	})
	v, ok := limits[name]
	if !ok {
		panic("orgrules: unknown limit " + name)
	}
	return v
}

// Limits returns the frozen store caps.
func Limits() store.OrgLimits {
	return store.OrgLimits{
		OrganizationsPerTenant:     Limit("organizations_per_tenant_max"),
		ConnectionsPerOrganization: Limit("enabled_connections_per_organization_max"),
		RolesPerMember:             Limit("roles_per_member_max"),
	}
}

const alphanumerics = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// NewID returns org_ followed by the frozen number of random alphanumerics.
func NewID() string {
	n := Limit("organization_id_random_chars")
	max := big.NewInt(int64(len(alphanumerics)))
	var b strings.Builder
	b.WriteString(IDPrefix)
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("orgrules: random source failed: " + err.Error())
		}
		b.WriteByte(alphanumerics[v.Int64()])
	}
	return b.String()
}

// ValidID reports whether id has the organization ID shape.
func ValidID(id string) bool {
	idOnce.Do(func() {
		idRE = regexp.MustCompile(fmt.Sprintf(`^%s[A-Za-z0-9]{%d}$`, IDPrefix, Limit("organization_id_random_chars")))
	})
	return idRE.MatchString(id)
}

// NormalizeOrganization validates in and returns a copy with defaults
// applied: an empty DisplayName becomes Name and an empty
// ThirdPartyClientAccess becomes "block". The copy shares nothing with in.
func NormalizeOrganization(in store.Organization) (store.Organization, error) {
	out := in
	out.ClientAssociation = nil
	out.ClientAssociationLoaded = false
	if out.DisplayName == "" {
		out.DisplayName = out.Name
	}
	if out.ThirdPartyClientAccess == "" {
		out.ThirdPartyClientAccess = ThirdPartyBlock
	}
	var errs []error
	if n := utf8.RuneCountInString(out.Name); n < 1 || n > Limit("name_chars_max") || !nameRE.MatchString(out.Name) {
		errs = append(errs, fmt.Errorf("name must be 1 to %d lowercase letters, digits, '-' or '_' starting with a letter or digit", Limit("name_chars_max")))
	}
	if n := utf8.RuneCountInString(out.DisplayName); n < 1 || n > Limit("display_name_chars_max") {
		errs = append(errs, fmt.Errorf("display_name must contain 1 to %d characters", Limit("display_name_chars_max")))
	}
	if out.ThirdPartyClientAccess != ThirdPartyBlock && out.ThirdPartyClientAccess != ThirdPartyAllow {
		errs = append(errs, fmt.Errorf("third_party_client_access must be %q or %q", ThirdPartyBlock, ThirdPartyAllow))
	}
	branding, err := normalizeBranding(in.Branding)
	if err != nil {
		errs = append(errs, err)
	}
	out.Branding = branding
	meta, err := normalizeMetadata(in.Metadata)
	if err != nil {
		errs = append(errs, err)
	}
	out.Metadata = meta
	if len(errs) > 0 {
		return store.Organization{}, errors.Join(errs...)
	}
	return out, nil
}

// normalizeBranding validates and deep-copies b. An empty branding is unset.
func normalizeBranding(b *store.OrgBranding) (*store.OrgBranding, error) {
	if b == nil || b.LogoURL == nil && b.Colors == nil {
		return nil, nil
	}
	out := &store.OrgBranding{}
	if b.LogoURL != nil {
		u, err := url.Parse(*b.LogoURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("branding.logo_url must be an https URL")
		}
		v := *b.LogoURL
		out.LogoURL = &v
	}
	if b.Colors != nil {
		c := *b.Colors
		if !hexColorRE.MatchString(c.Primary) || !hexColorRE.MatchString(c.PageBackground) {
			return nil, fmt.Errorf("branding.colors needs both primary and page_background as HTML hex colors")
		}
		out.Colors = &c
	}
	return out, nil
}

// normalizeMetadata validates and copies m. An empty map is unset (nil).
func normalizeMetadata(m map[string]string) (map[string]string, error) {
	if len(m) == 0 {
		return nil, nil
	}
	if len(m) > Limit("metadata_keys_max") {
		return nil, fmt.Errorf("metadata must have at most %d keys", Limit("metadata_keys_max"))
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if n := utf8.RuneCountInString(k); n < 1 || n > Limit("metadata_key_chars_max") || !metaKeyRE.MatchString(k) {
			return nil, fmt.Errorf("metadata key %q is invalid", k)
		}
		if n := utf8.RuneCountInString(v); n < 1 || n > Limit("metadata_value_chars_max") {
			return nil, fmt.Errorf("metadata value for %q must contain 1 to %d characters", k, Limit("metadata_value_chars_max"))
		}
		out[k] = v
	}
	return out, nil
}

// IsEnterprise reports whether strategy is an enterprise connection
// (federated and not social).
func IsEnterprise(strategy string) bool {
	return rules.IsFederated(strategy) && !rules.IsSocial(strategy)
}

// ValidateConnection checks the flags of an enabled connection against the
// connection's strategy: show_as_button may be false only on enterprise
// strategies, is_signup_enabled only on database connections and only with
// assign_membership_on_login.
func ValidateConnection(strategy string, oc store.OrganizationConnection) error {
	if oc.ConnectionID == "" {
		return errors.New("connection_id is required")
	}
	if !oc.ShowAsButton && !IsEnterprise(strategy) {
		return errors.New("show_as_button can be false only for enterprise connections")
	}
	if oc.IsSignupEnabled {
		if strategy != store.StrategyDatabase {
			return errors.New("is_signup_enabled is allowed only for database connections")
		}
		if !oc.AssignMembershipOnLogin {
			return errors.New("is_signup_enabled requires assign_membership_on_login")
		}
	}
	return nil
}

// Sort fields accepted by organization lists.
const (
	SortName        = "name"
	SortDisplayName = "display_name"
	SortCreatedAt   = "created_at"
)

// ParseSort parses "field:1" or "field:-1". An empty value returns an empty
// field. Only name, display_name and created_at are accepted.
func ParseSort(s string) (field string, desc bool, err error) {
	if s == "" {
		return "", false, nil
	}
	f, dir, ok := strings.Cut(s, ":")
	if !ok || !slices.Contains([]string{SortName, SortDisplayName, SortCreatedAt}, f) || dir != "1" && dir != "-1" {
		return "", false, fmt.Errorf("invalid sort %q", s)
	}
	return f, dir == "-1", nil
}

// PageMode is the pagination style of a normalized OrgPage.
type PageMode int

const (
	Offset PageMode = iota
	Checkpoint
)

// NormalizePage applies defaults and bounds. Checkpoint mode applies when
// From is set or Take is non-zero; Page is then ignored. It returns the mode
// or an error for out-of-range values.
func NormalizePage(p *store.OrgPage) (PageMode, error) {
	if p.Page < 0 || p.PerPage < 0 || p.Take < 0 || p.PerPage > Limit("per_page_max") || p.Take > Limit("take_max") || p.Page > Limit("page_max") {
		return Offset, errors.New("invalid pagination")
	}
	if p.From != "" || p.Take > 0 {
		if p.Take == 0 {
			p.Take = Limit("take_default")
		}
		p.Page = 0
		return Checkpoint, nil
	}
	if p.PerPage == 0 {
		p.PerPage = Limit("per_page_default")
	}
	return Offset, nil
}

// Cursor is the decoded checkpoint position: the last item returned,
// bound to a tenant and list.
type Cursor struct {
	Scope string `json:"s"`
	Sort  string `json:"o"`
	Key   string `json:"k"`
	ID    string `json:"i"`
}

// EncodeCursor returns the opaque checkpoint token.
func EncodeCursor(c Cursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor parses a token and checks it belongs to scope and sort.
func DecodeCursor(token, scope, sort string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	var c Cursor
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Scope != scope || c.Sort != sort {
		return Cursor{}, errors.New("invalid cursor")
	}
	return c, nil
}
