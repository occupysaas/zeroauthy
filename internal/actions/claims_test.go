package actions

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestFilterClaims(t *testing.T) {
	reserved := []string{"acr", "act", "active", "amr", "at_hash", "ath", "attest", "aud", "auth_time", "authorization_details",
		"azp", "c_hash", "client_id", "cnf", "cty", "dest", "entitlements", "events", "exp", "groups", "gty", "htm",
		"htu", "iat", "internalService", "iss", "jcard", "jku", "jti", "jwe", "jwk", "kid", "may_act", "mky", "nbf",
		"nonce", "object_id", "org_id", "org_name", "orig", "origid", "permissions", "roles", "rph", "s_hash",
		"sid", "sip_callid", "sip_cseq_num", "sip_date", "sip_from_tag", "sip_via_branch", "sub", "sub_jwk",
		"toe", "txn", "typ", "uuid", "vot", "vtm", "x5t#S256", "scope"}
	custom := map[string]any{
		"https://example.com/ok":       1,
		"urn:example:ok":               2,
		"plain":                        3,
		"https://auth0.com/x":          4,
		"https://tenant.auth0.com/x":   5,
		"http://webtask.io/x":          6,
		"https://a.webtask.run/x":      7,
		"urn:auth0:x":                  8,
		"URN:AUTH0:y":                  9,
		"https://example.com/existing": 10,
		"https://auth0.com.evil.test/": 11,
	}
	for _, r := range reserved {
		custom[r] = "x"
	}
	existing := map[string]any{"https://example.com/existing": "kept", "sub": "auth0|u"}
	keys := func(m map[string]any) string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	got, err := FilterClaims(ClaimAccessToken, existing, custom, false)
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(got); k != "https://auth0.com.evil.test/,https://example.com/ok,plain,urn:example:ok" {
		t.Fatalf("access claims = %s", k)
	}
	got, err = FilterClaims(ClaimAccessToken, existing, custom, true)
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(got); k != "https://auth0.com.evil.test/,https://example.com/ok,urn:example:ok" {
		t.Fatalf("Management API access claims = %s", k)
	}
	got, err = FilterClaims(ClaimIDToken, existing, custom, true)
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(got); k != "https://auth0.com.evil.test/,https://example.com/ok,plain,urn:example:ok" {
		t.Fatalf("ID claims = %s", k)
	}
	if _, err := FilterClaims(ClaimIDToken, nil, map[string]any{"https://x.test/big": strings.Repeat("x", 100_000)}, false); !errors.Is(err, ErrClaimsTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
	if got, err := FilterClaims(ClaimIDToken, nil, nil, false); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestApplyScopes(t *testing.T) {
	var nilEff *Effects
	if got := nilEff.ApplyScopes([]string{"a"}, []string{"a", "b"}); strings.Join(got, " ") != "a b" {
		t.Fatal(got)
	}
	e := &Effects{AddScopes: []string{"x", "b"}, RemoveScopes: []string{"a"}}
	if got := e.ApplyScopes([]string{"a", "b"}, []string{"a", "b"}); strings.Join(got, " ") != "b x" {
		t.Fatal(got)
	}
}

// TestCommandsRejectUnknown: Go is the authority on commands; anything the
// runner reports outside the trigger's api fails the flow.
func TestCommandsRejectUnknown(t *testing.T) {
	raw := func(s string) []json.RawMessage {
		var out []json.RawMessage
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, c := range []struct {
		trigger, op, args string
		ok                bool
	}{
		{TriggerPostLogin, "access.foo", `[]`, false},
		{TriggerPostLogin, "multifactor.enable", `["any"]`, false},
		{TriggerPostLogin, "unsupported", `["session.revoke"]`, false},
		{TriggerPostLogin, "accessToken.addScope", `["x"]`, true},
		{TriggerPostLogin, "accessToken.addScope", `["x y"]`, false},
		{TriggerPostLogin, "accessToken.addScope", `["x", "y"]`, false},
		{TriggerCredentialsExchange, "accessToken.addScope", `["x"]`, false},
		{TriggerCredentialsExchange, "user.setAppMetadata", `["a", 1]`, false},
		{TriggerCredentialsExchange, "access.deny", `["invalid_scope"]`, true},
		{TriggerCredentialsExchange, "access.deny", `["nope", "r"]`, false},
		{TriggerPostLogin, "transaction.setMetadata", `["k", "v"]`, true},
		{TriggerPostLogin, "transaction.setMetadata", `["` + strings.Repeat("k", 65) + `", "v"]`, false},
		{TriggerPostLogin, "transaction.setMetadata", `["k", "` + strings.Repeat("v", 8193) + `"]`, false},
		{TriggerPostLogin, "cache.set", `["k", "v", {"ttl": 5}]`, true},
		{TriggerPostLogin, "cache.set", `["k", "v", {"other": 5}]`, false},
		{TriggerPostLogin, "cache.set", `["` + strings.Repeat("k", 65) + `", "v", {}]`, false},
		{TriggerPostLogin, "redirect.sendUserTo", `["javascript:alert(1)"]`, false},
		{TriggerPostLogin, "redirect.sendUserTo", `["https://example.test/"]`, false},
		{TriggerPostLogin, "access.deny", `["fine reason"]`, true},
		{TriggerPostLogin, "access.deny", `["` + strings.Repeat("r", 513) + `"]`, false},
		{TriggerPostLogin, "validation.error", `["code", "message"]`, true},
		{TriggerPostLogin, "validation.error", `["` + strings.Repeat("c", 129) + `", "m"]`, false},
		{TriggerPostLogin, "validation.error", `["a\\b", "m"]`, false},
		{TriggerCredentialsExchange, "access.deny", `["invalid_scope", "bad\u0001"]`, false},
	} {
		f := newAccum(c.trigger, nil, nil, true)
		err := f.apply(command{Op: c.op, Args: raw(c.args)})
		if (err == nil) != c.ok {
			t.Errorf("%s %s %s: err = %v, want ok=%v", c.trigger, c.op, c.args, err, c.ok)
		}
	}
	// Transaction metadata total is bounded.
	f := newAccum(TriggerPostLogin, nil, nil, true)
	for i := range 2 {
		if err := f.apply(command{Op: "transaction.setMetadata", Args: raw(`["k` + string(rune('0'+i)) + `", "` + strings.Repeat("v", 8000) + `"]`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.apply(command{Op: "transaction.setMetadata", Args: raw(`["k9", "` + strings.Repeat("v", 500) + `"]`)}); err == nil {
		t.Fatal("transaction metadata total not bounded")
	}
}
