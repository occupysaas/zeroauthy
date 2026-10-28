package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
)

// ErrClaimsTooLarge reports custom claims over Auth0's 100 kB payload limit;
// the flow fails closed (spec §7).
var ErrClaimsTooLarge = errors.New("actions: custom claims exceed the payload limit")

// ClaimTarget names the token a custom claim is meant for.
type ClaimTarget int

const (
	ClaimAccessToken ClaimTarget = iota
	ClaimIDToken
)

// reservedClaims is Auth0's published list of restricted claim names
// (https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims)
// plus "scope", which spec §7 names.
var reservedClaims = map[string]bool{}

func init() {
	for _, c := range strings.Fields(`acr act active amr at_hash ath attest aud auth_time authorization_details
		azp c_hash client_id cnf cty dest entitlements events exp groups gty htm htu iat internalService iss
		jcard jku jti jwe jwk kid may_act mky nbf nonce object_id org_id org_name orig origid permissions roles
		rph s_hash sid sip_callid sip_cseq_num sip_date sip_from_tag sip_via_branch sub sub_jwk toe txn typ
		uuid vot vtm x5t#S256 scope`) {
		reservedClaims[c] = true
	}
}

// restrictedHosts are Auth0's own domains, refused as claim namespaces, and
// zeroauthy's (tenant.OperatorClaim lives under zeroauthy.dev).
var restrictedHosts = []string{"auth0.com", "webtask.io", "webtask.run", "zeroauthy.dev"}

// namespaced reports whether a claim name carries a namespace: an http(s)
// URL or a URN.
func namespaced(name string) bool {
	l := strings.ToLower(name)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "urn:")
}

// restrictedNamespace reports a claim namespaced under urn:auth0 or an
// Auth0 domain (or one of its subdomains).
func restrictedNamespace(name string) bool {
	l := strings.ToLower(name)
	if strings.HasPrefix(l, "urn:auth0") || strings.HasPrefix(l, "urn:zeroauthy") {
		return true
	}
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return false
	}
	u, err := url.Parse(l)
	if err != nil {
		return true // an unparsable namespace is not added
	}
	host := u.Hostname()
	for _, h := range restrictedHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// FilterClaims returns the custom claims that may be added to a token:
// reserved names, names the token already carries (existing) and Auth0
// namespaces are silently dropped, as on Auth0; access tokens for the
// tenant's Management API audience also drop non-namespaced claims. A
// result over the 100 kB payload limit is ErrClaimsTooLarge.
func FilterClaims(kind ClaimTarget, existing map[string]any, custom map[string]any, mgmtAudience bool) (map[string]any, error) {
	out := make(map[string]any, len(custom))
	for name, v := range custom {
		if name == "" || reservedClaims[name] || restrictedNamespace(name) {
			continue
		}
		if _, ok := existing[name]; ok {
			continue
		}
		if kind == ClaimAccessToken && mgmtAudience && !namespaced(name) {
			continue
		}
		out[name] = v
	}
	if err := checkClaimsSize(out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkClaimsSize(m map[string]any) error {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("actions: custom claims are not JSON: %w", err)
	}
	if max := actionsrules.Inventory().Limits["custom_claims_bytes_max"]; len(b) > max {
		return fmt.Errorf("%w (%d bytes, at most %d)", ErrClaimsTooLarge, len(b), max)
	}
	return nil
}

// ApplyScopes returns the final access-token scope: filtered (the scopes
// left after target edits, API policy, RBAC and consent, spec §7) plus
// accessToken.addScope minus accessToken.removeScope, which bypass those
// checks as on Auth0. base is the scope set before Actions ran; it does not
// change the result and is kept for callers that log the difference. A nil
// receiver returns filtered unchanged.
func (e *Effects) ApplyScopes(base []string, filtered []string) []string {
	out := slices.Clone(filtered)
	if e == nil {
		return out
	}
	for _, s := range e.AddScopes {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return slices.DeleteFunc(out, func(s string) bool { return slices.Contains(e.RemoveScopes, s) })
}
