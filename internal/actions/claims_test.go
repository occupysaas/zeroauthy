package actions

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
)

func TestFilterClaims(t *testing.T) {
	reserved := []string{"acr", "act", "active", "amr", "at_hash", "ath", "attest", "aud", "auth_time", "authorization_details",
		"azp", "c_hash", "client_id", "cnf", "cty", "dest", "entitlements", "events", "exp", "groups", "gty", "htm",
		"htu", "iat", "internalService", "iss", "jcard", "jku", "jti", "jwe", "jwk", "kid", "may_act", "mky", "nbf",
		"nonce", "object_id", "org_id", "org_name", "orig", "origid", "permissions", "roles", "rph", "s_hash",
		"sid", "sip_callid", "sip_cseq_num", "sip_date", "sip_from_tag", "sip_via_branch", "sub", "sub_jwk",
		"toe", "txn", "typ", "uuid", "vot", "vtm", "x5t#S256", "scope"}
	custom := map[string]any{
		"https://example.com/ok":         1,
		"urn:example:ok":                 2,
		"plain":                          3,
		"https://auth0.com/x":            4,
		"https://tenant.auth0.com/x":     5,
		"http://webtask.io/x":            6,
		"https://a.webtask.run/x":        7,
		"urn:auth0:x":                    8,
		"URN:AUTH0:y":                    9,
		"https://example.com/existing":   10,
		"https://auth0.com.evil.test/":   11,
		"https://zeroauthy.dev/operator": 12,
		"https://x.zeroauthy.dev/y":      13,
		"urn:zeroauthy:z":                14,
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
		{TriggerPostLogin, "access.deny", `["` + strings.Repeat("r", 513) + `"]`, true}, // truncated
		{TriggerPostLogin, "validation.error", `["code", "message"]`, true},
		{TriggerPostLogin, "validation.error", `["` + strings.Repeat("c", 129) + `", "m"]`, false},
		{TriggerPostLogin, "validation.error", `["a\\b", "m"]`, false},
		{TriggerCredentialsExchange, "access.deny", `["invalid_scope", "bad\u0001"]`, true}, // sanitized
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

// TestDenyReasonSanitized: deny reasons and validation.error messages reach
// OAuth error_description, so characters outside the RFC 6749 charset are
// replaced and the text is cut at 512 bytes; the flow still denies (a
// localized reason is not a server error). Error codes stay strict.
func TestDenyReasonSanitized(t *testing.T) {
	for _, c := range []struct {
		trigger, op, args, code, reason string
	}{
		{TriggerPostLogin, "access.deny", `["Zugriff f\u00fcr \u00c4rzte verweigert"]`, "access_denied", "Zugriff f?r ?rzte verweigert"},
		{TriggerPostLogin, "access.deny", `["say \"no\" \\ now\n"]`, "access_denied", "say ?no? ? now?"},
		{TriggerPostLogin, "access.deny", `["\u65e5\u672c"]`, "access_denied", "??"},
		{TriggerPostLogin, "access.deny", `["` + strings.Repeat("r", 600) + `"]`, "access_denied", strings.Repeat("r", 512)},
		{TriggerPostLogin, "validation.error", `["bad_thing", "Grö\u00dfe"]`, "bad_thing", "Gr??e"},
		{TriggerCredentialsExchange, "access.deny", `["invalid_scope", "nicht erlaubt: \u00df"]`, "invalid_scope", "nicht erlaubt: ?"},
	} {
		var args []json.RawMessage
		if err := json.Unmarshal([]byte(c.args), &args); err != nil {
			t.Fatal(err)
		}
		f := newAccum(c.trigger, nil, nil, false)
		if err := f.apply(command{Op: c.op, Args: args}); err != nil {
			t.Errorf("%s %s: %v", c.op, c.args, err)
			continue
		}
		if f.denied == nil || f.denied.Code != c.code || f.denied.Reason != c.reason {
			t.Errorf("%s %s: denial = %+v, want %s %q", c.op, c.args, f.denied, c.code, c.reason)
		}
	}
}

// TestRequestBodyStripsCredentials: event.request.body never carries the
// request's credentials (the authorization code too, for its grant).
func TestRequestBodyStripsCredentials(t *testing.T) {
	body := map[string]any{"grant_type": "authorization_code", "code": "c", "password": "p", "client_secret": "s",
		"client_assertion": "a", "code_verifier": "v", "refresh_token": "r", "device_code": "d", "username": "u", "scope": "openid"}
	got := requestEvent(RequestInfo{Body: body}, "h", false)["body"].(map[string]any)
	want := map[string]any{"grant_type": "authorization_code", "username": "u", "scope": "openid"}
	if b, w := mustMarshal(t, got), mustMarshal(t, want); b != w {
		t.Fatalf("body = %s, want %s", b, w)
	}
	if len(body) != 10 {
		t.Fatal("the input body was modified")
	}
	// Another grant's "code" parameter is not a credential.
	got = requestEvent(RequestInfo{Body: map[string]any{"grant_type": "password", "code": "x"}}, "h", false)["body"].(map[string]any)
	if got["code"] != "x" {
		t.Fatalf("body = %v", got)
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSealEffects: sealed effects open only under the same tenant, purpose
// and binding, and keep claims and scope edits.
func TestSealEffects(t *testing.T) {
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &Effects{AccessClaims: map[string]any{"https://x/a": "secret"}, IDClaims: map[string]any{"https://x/i": 1.0},
		AddScopes: []string{"a"}, RemoveScopes: []string{"b"}, Target: &TargetEdit{Scopes: []string{}},
		AppMetadata: map[string]any{"m": 1}, TxnMetadata: map[string]any{"t": 1}}
	sealed, err := SealEffects(w, "t1", SealCode, e, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("claims stored in the clear")
	}
	got, err := OpenEffects(w, "t1", SealCode, sealed, "hash")
	if err != nil {
		t.Fatal(err)
	}
	want := &Effects{AccessClaims: e.AccessClaims, IDClaims: e.IDClaims, AddScopes: e.AddScopes, RemoveScopes: e.RemoveScopes,
		Target: &TargetEdit{Scopes: []string{}}}
	if mustMarshal(t, got) != mustMarshal(t, want) {
		t.Fatalf("opened %+v, want %+v", got, want)
	}
	for _, c := range [][3]string{{"t2", SealCode, "hash"}, {"t1", SealDevice, "hash"}, {"t1", SealCode, "other"}} {
		if _, err := OpenEffects(w, c[0], c[1], sealed, c[2]); err == nil {
			t.Errorf("opened under %v", c)
		}
	}
}
