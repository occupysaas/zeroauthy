package rules

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

func githubInput(extra map[string]any) Input {
	o := map[string]any{"client_id": "Iv1.example", "client_secret": "throwaway"}
	maps.Copy(o, extra)
	return Input{Strategy: GitHub, Name: "github", Options: o}
}

func TestGitHubScopeFlags(t *testing.T) {
	for _, f := range GitHubScopeFlags {
		s, errs := Parse(githubInput(map[string]any{f.Option: true}))
		if len(errs) > 0 {
			t.Fatalf("%s: %v", f.Option, errs)
		}
		n := 0
		for _, sc := range s.Scopes {
			if sc == f.Scope {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s: scopes %v", f.Option, s.Scopes)
		}
		if slices.Contains(s.Scopes, "offline_access") {
			t.Fatalf("%s: offline_access", f.Option)
		}
	}
	cases := []struct {
		name string
		o    map[string]any
		want []string
	}{
		{"default", nil, []string{"user:email"}},
		{"no email", map[string]any{"email": false}, []string{}},
		{"profile false", map[string]any{"profile": false}, []string{"user:email"}},
		{"order", map[string]any{"read_user": true, "email": true}, []string{"user:email", "read:user"}},
	}
	for _, c := range cases {
		s, errs := Parse(githubInput(c.o))
		if len(errs) > 0 || !slices.Equal(s.Scopes, c.want) {
			t.Fatalf("%s: %v %v", c.name, s.Scopes, errs)
		}
		if s.AuthorizationURL != GitHubAuthorizationURL || s.TokenURL != GitHubTokenURL || s.DiscoveryURL != "" {
			t.Fatalf("%s: endpoints", c.name)
		}
	}
	if GitHubEmailEnabled(map[string]any{}) != true || GitHubEmailEnabled(map[string]any{"email": false}) {
		t.Fatal("GitHubEmailEnabled")
	}
}

// The adapter infers the email option from the effective scope containing
// user:email, so no flag may map to it.
func TestGitHubScopeFlagsExcludeUserEmail(t *testing.T) {
	for _, f := range GitHubScopeFlags {
		if f.Scope == "user:email" {
			t.Fatalf("flag %q maps to user:email", f.Option)
		}
	}
}

func TestGitHubScopeFlagsMatchInventory(t *testing.T) {
	raw, err := os.ReadFile("../inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		ProviderProtocol struct {
			GitHub struct {
				ScopeFlags map[string]string `json:"scope_flags"`
			} `json:"github"`
		} `json:"provider_protocol"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	want := inv.ProviderProtocol.GitHub.ScopeFlags
	delete(want, "email")
	delete(want, "profile")
	got := map[string]string{}
	for _, f := range GitHubScopeFlags {
		got[f.Option] = f.Scope
	}
	if !maps.Equal(got, want) {
		t.Fatalf("flags differ from inventory: %v vs %v", got, want)
	}
}

func TestGitHubScopeInput(t *testing.T) {
	_, errs := Parse(githubInput(map[string]any{"read_user": true, "scope": []any{"read:user", "user:email"}}))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	_, errs = Parse(githubInput(map[string]any{"scope": []any{"repo"}, "repo": false}))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "options.scope must match") {
		t.Fatalf("%v", errs)
	}
	if _, errs = Parse(githubInput(map[string]any{"scope": "repo"})); len(errs) == 0 {
		t.Fatal("string scope accepted")
	}
}

func TestGitHubRejections(t *testing.T) {
	bad := map[string]map[string]any{
		"freeform":    {"freeform_scopes": []any{"x"}},
		"flag type":   {"repo": "true"},
		"auth url":    {"authorizationURL": "https://x.example/a"},
		"token url":   {"tokenURL": "https://x.example/t"},
		"api host":    {"api_host": "x.example"},
		"enterprise":  {"github_enterprise_url": "https://x.example"},
		"device flow": {"device_flow": true},
	}
	for name, o := range bad {
		if _, errs := Parse(githubInput(o)); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if _, errs := Parse(githubInput(map[string]any{"freeform_scopes": []any{}})); len(errs) > 0 {
		t.Fatal(errs)
	}
}

func TestGitHubRequiredOptions(t *testing.T) {
	in := githubInput(nil)
	delete(in.Options, "client_id")
	if _, errs := Parse(in); len(errs) == 0 {
		t.Fatal("missing client_id accepted")
	}
	in = githubInput(nil)
	delete(in.Options, "client_secret")
	if _, errs := Parse(in); len(errs) == 0 {
		t.Fatal("missing client_secret accepted")
	}
	in.HasSealedSecret = true
	if _, errs := Parse(in); len(errs) > 0 {
		t.Fatal(errs)
	}
}

func TestGitHubConnectedAccounts(t *testing.T) {
	for v, ok := range map[any]bool{true: false, "true": false, 1: false, false: true, nil: true} {
		in := githubInput(nil)
		in.ConnectedAccounts = map[string]any{"active": v}
		if _, errs := Parse(in); (len(errs) == 0) != ok {
			t.Errorf("active=%v: %v", v, errs)
		}
	}
	if _, errs := Parse(githubInput(nil)); len(errs) > 0 {
		t.Fatal(errs)
	}
}
