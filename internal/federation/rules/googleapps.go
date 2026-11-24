package rules

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// GoogleApps is the Google Workspace enterprise strategy (Plan 37c Phase C).
const GoogleApps = "google-apps"

// Google Directory API scopes requested by the administrator consent of a
// directory provisioning configuration (never during user login).
const (
	DirectoryUserScope  = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	DirectoryGroupScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

// GoogleAppsSettings are the validated google-apps options.
type GoogleAppsSettings struct {
	// Domain is the primary Workspace domain, lowercase ASCII; the ID token's
	// hd claim must equal it.
	Domain string
	// MapUserIDToID selects Google's numeric subject over the email address
	// as the identity's user_id; immutable after creation.
	MapUserIDToID bool
	// APIEnableUsers and APIEnableGroups gate directory provisioning.
	APIEnableUsers, APIEnableGroups bool
}

// googleAppsStored are google-apps options zeroauthy stores and returns
// without acting on them (D-0150 LR37c-14): Auth0's login-time extended
// attributes.
var googleAppsStored = []string{"ext_agreed_terms", "ext_groups", "ext_groups_extended", "ext_is_admin", "ext_is_suspended"}

// googleAppsManaged are Auth0's administrator tokens. zeroauthy obtains its
// own through the directory provisioning consent and never accepts them
// through the API.
var googleAppsManaged = []string{"admin_access_token", "admin_access_token_expiresin", "admin_refresh_token"}

// GoogleAppsDomain validates a Workspace domain and returns it as lowercase
// ASCII.
func GoogleAppsDomain(v any) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("options.domain is required")
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(s, ".")))
	if err != nil || !validDNS(ascii) || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("options.domain must be a DNS name")
	}
	return ascii, nil
}

func parseGoogleApps(o map[string]any, out *Settings) []error {
	// Auth0 exports scope as ["email", "profile"]; openid is implicit.
	rest := make(map[string]any, len(o))
	for k, v := range o {
		if k != "scope" {
			rest[k] = v
		}
	}
	errs := parseGoogle(rest, out)
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if v, ok := o["scope"]; ok && v != nil {
		list, isList := v.([]any)
		var got []string
		for _, e := range list {
			s, isStr := e.(string)
			if !isStr {
				isList = false
				break
			}
			if s != "openid" {
				got = append(got, s)
			}
		}
		if !isList || !sameSet(append(got, "openid"), out.Scopes) {
			fail("options.scope must match the email and profile flags")
		}
	}
	g := &GoogleAppsSettings{APIEnableUsers: true}
	domain, err := GoogleAppsDomain(o["domain"])
	if err != nil {
		errs = append(errs, err)
	}
	g.Domain = domain
	if v, ok := o["tenant_domain"]; ok && v != nil {
		td, err := GoogleAppsDomain(v)
		if err != nil || td != domain {
			fail("options.tenant_domain must equal options.domain")
		}
	}
	flag := func(k string, def bool) bool {
		v, ok := o[k]
		if !ok || v == nil {
			return def
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", k)
			return def
		}
		return b
	}
	g.MapUserIDToID = flag("map_user_id_to_id", false)
	g.APIEnableUsers = flag("api_enable_users", true)
	g.APIEnableGroups = flag("api_enable_groups", false)
	for _, k := range googleAppsStored {
		flag(k, false)
	}
	if flag("allow_setting_login_scopes", false) {
		fail("options.allow_setting_login_scopes: additional login scopes are not supported")
	}
	if flag("handle_login_from_social", false) {
		fail("options.handle_login_from_social: routing Google social logins is not supported")
	}
	for _, k := range googleAppsManaged {
		if _, ok := o[k]; ok {
			fail("options.%s is managed by the directory provisioning consent", k)
		}
	}
	out.GoogleApps = g
	return errs
}
