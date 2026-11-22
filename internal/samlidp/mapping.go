// Package samlidp is zeroauthy as a SAML 2.0 identity provider: the samlp
// application add-on (Plan 37a, D-0130). Requests run through the normal
// authorization flow (internal/authz) with a server-only SAML binding; this
// package parses requests and builds the signed responses.
package samlidp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// auth0Namespace prefixes claims sent without a mapping (passthrough).
const auth0Namespace = "http://schemas.auth0.com/"

// defaultNames are Auth0's default attribute names for profile fields
// (customize SAML assertions; node-samlp PassportProfileMapper, D-0130).
var defaultNames = map[string]string{
	"user_id": samlcore.ClaimNameIdentifier, "email": samlcore.ClaimEmail, "name": samlcore.ClaimName,
	"given_name": samlcore.ClaimGivenName, "family_name": samlcore.ClaimSurname, "upn": samlcore.ClaimUPN,
	"groups": samlcore.ClaimGroups,
}

// defaultProbes are Auth0's default name identifier probes.
var defaultProbes = []string{samlcore.ClaimNameIdentifier, samlcore.ClaimEmail, samlcore.ClaimName}

func flag(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// mapped is an assertion's attributes and the chosen NameID.
type mapped struct {
	Attributes []samlcore.Attribute
	NameID     string
}

// profile is the user's root profile as claims. Metadata is not included:
// it reaches the assertion only through an explicit mapping.
func profile(u *store.User, extra map[string]any) map[string]any {
	p := map[string]any{"user_id": u.UserID, "email_verified": u.EmailVerified}
	for k, v := range map[string]string{"email": u.Email, "name": u.Name, "given_name": u.GivenName, "family_name": u.FamilyName,
		"nickname": u.Nickname, "picture": u.Picture} {
		if v != "" {
			p[k] = v
		}
	}
	if !u.CreatedAt.IsZero() {
		p["created_at"] = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !u.UpdatedAt.IsZero() {
		p["updated_at"] = u.UpdatedAt.UTC().Format(time.RFC3339)
	}
	for k, v := range extra {
		if k != "app_metadata" && k != "user_metadata" {
			p[k] = v
		}
	}
	return p
}

// lookup resolves a mapping key: a profile field, or a dotted path into
// app_metadata or user_metadata.
func lookup(u *store.User, p map[string]any, key string) (any, bool) {
	if v, ok := p[key]; ok {
		return v, true
	}
	parts := strings.Split(key, ".")
	var cur any
	switch parts[0] {
	case "app_metadata":
		cur = u.AppMetadata
	case "user_metadata":
		cur = u.UserMetadata
	default:
		return nil, false
	}
	for _, part := range parts[1:] {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

// values renders a claim value as attribute values.
func values(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case bool:
		return []string{strconv.FormatBool(t)}
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	case int:
		return []string{strconv.Itoa(t)}
	case []string:
		return append([]string(nil), t...)
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, values(e)...)
		}
		return out
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return []string{fmt.Sprint(t)}
		}
		return []string{string(raw)}
	}
}

// buildAttributes maps the user to SAML attributes per the add-on.
func buildAttributes(u *store.User, addon *store.SAMLAddon, extra map[string]any) mapped {
	p := profile(u, extra)
	if flag(addon.CreateUpnClaim, true) && u.Email != "" {
		p["upn"] = u.Email
	}
	names := map[string][]string{}
	for field, name := range defaultNames {
		names[field] = []string{name}
	}
	for field, mappedNames := range addon.Mappings {
		names[field] = mappedNames
	}
	var out []samlcore.Attribute
	add := func(name string, vals []string) {
		if len(vals) > 0 && name != "" {
			out = append(out, samlcore.Attribute{Name: name, Values: vals})
		}
	}
	fields := make([]string, 0, len(names))
	for f := range names {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, field := range fields {
		v, ok := lookup(u, p, field)
		if !ok {
			continue
		}
		for _, name := range names[field] {
			add(name, values(v))
		}
	}
	if flag(addon.PassthroughClaimsWithNoMapping, true) {
		rest := make([]string, 0, len(p))
		for f := range p {
			if _, mappedField := names[f]; !mappedField {
				rest = append(rest, f)
			}
		}
		sort.Strings(rest)
		asIs := flag(addon.MapUnknownClaimsAsIs, false)
		for _, f := range rest {
			name := auth0Namespace + f
			if asIs {
				name = f
			}
			add(name, values(p[f]))
		}
	}
	if flag(addon.MapIdentities, true) && len(u.Identities) > 0 {
		id := u.Identities[0]
		prefix := auth0Namespace + "identities/default/"
		add(prefix+"provider", values(id.Provider))
		add(prefix+"connection", values(id.Connection))
		add(prefix+"user_id", values(id.UserID))
		add(prefix+"isSocial", values(rules.IsSocial(id.Provider)))
	}
	probes := addon.NameIdentifierProbes
	if len(probes) == 0 {
		probes = defaultProbes
	}
	m := mapped{Attributes: out}
	for _, probe := range probes {
		for _, a := range out {
			if a.Name == probe && len(a.Values) > 0 && a.Values[0] != "" {
				m.NameID = a.Values[0]
				return m
			}
		}
	}
	m.NameID = u.UserID
	return m
}
