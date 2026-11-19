package rules

import (
	"fmt"
	"slices"
	"strings"
)

// GitHub endpoints are fixed; GitHub Enterprise hosts are not supported.
const (
	GitHubAuthorizationURL = "https://github.com/login/oauth/authorize"
	GitHubTokenURL         = "https://github.com/login/oauth/access_token"
	GitHubAPIBase          = "https://api.github.com"
)

// GitHubScopeFlags maps each boolean scope option to the GitHub OAuth scope it
// adds, in the order of the inventory's provider_protocol.github.scope_flags.
var GitHubScopeFlags = []struct{ Option, Scope string }{
	{"admin_org", "admin:org"},
	{"admin_public_key", "admin:public_key"},
	{"admin_repo_hook", "admin:repo_hook"},
	{"delete_repo", "delete_repo"},
	{"follow", "user:follow"},
	{"gist", "gist"},
	{"notifications", "notifications"},
	{"public_repo", "public_repo"},
	{"read_org", "read:org"},
	{"read_public_key", "read:public_key"},
	{"read_repo_hook", "read:repo_hook"},
	{"read_user", "read:user"},
	{"repo", "repo"},
	{"repo_deployment", "repo_deployment"},
	{"repo_status", "repo:status"},
	{"write_org", "write:org"},
	{"write_public_key", "write:public_key"},
	{"write_repo_hook", "write:repo_hook"},
}

// githubRejected are options GitHub connections never accept.
var githubRejected = []string{"authorizationURL", "tokenURL", "api_host", "github_enterprise_url", "device_flow"}

// GitHubEmailEnabled reports the email flag; it defaults to true.
func GitHubEmailEnabled(o map[string]any) bool {
	b, ok := o["email"].(bool)
	return !ok || b
}

func parseGitHub(o, connectedAccounts map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	flag := func(k string, def bool) bool {
		v, ok := o[k]
		if !ok {
			return def
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", k)
			return def
		}
		return b
	}
	for _, k := range githubRejected {
		if _, ok := o[k]; ok {
			fail("options.%s is not supported on github connections", k)
		}
	}
	if v, ok := connectedAccounts["active"]; ok && v != nil && v != false {
		fail("connected_accounts.active is not supported on github connections")
	}
	if v, ok := o["freeform_scopes"]; ok && v != nil {
		if list, isList := v.([]any); !isList || len(list) > 0 {
			fail("options.freeform_scopes: freeform scopes are not supported")
		}
	}
	flag("profile", true)
	scopes := []string{}
	if flag("email", true) {
		scopes = append(scopes, "user:email")
	}
	for _, f := range GitHubScopeFlags {
		if flag(f.Option, false) && !slices.Contains(scopes, f.Scope) {
			scopes = append(scopes, f.Scope)
		}
	}
	if v, ok := o["scope"]; ok && v != nil {
		list, isList := v.([]any)
		var got []string
		valid := isList
		for _, e := range list {
			s, isStr := e.(string)
			if !isStr {
				valid = false
				break
			}
			got = append(got, s)
		}
		if !valid {
			fail("options.scope must be an array of strings")
		} else if !sameSet(got, scopes) {
			fail("options.scope must match the scope flags (%s)", strings.Join(scopes, " "))
		}
	}
	out.Scopes = scopes
	out.AuthorizationURL, out.TokenURL = GitHubAuthorizationURL, GitHubTokenURL
	return errs
}
