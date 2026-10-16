package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func pw(clientID, secret, username, password string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {username}, "password": {password}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPasswordGrant(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
		form: pw("ropg", "ropg-secret", "Alice@Acme.test ", "alice password 1", "audience", "https://api.acme.test", "scope", "openid read:things offline_access")})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["gty"] != "password" || at["azp"] != "ropg" || !strings.HasPrefix(at["sub"].(string), "auth0|") {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["id_token"].(string))
	if idt["sid"] != nil || idt["auth_time"] != float64(fixedNow().Unix()) || idt["email"] != nil {
		t.Fatalf("id token = %v", idt)
	}
	if body["refresh_token"] == nil || body["scope"] != "openid read:things offline_access" {
		t.Fatalf("body = %v", body)
	}
}

func TestPasswordRealmGrant(t *testing.T) {
	f := newFixture(t)
	form := pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")
	form.Set("grant_type", GrantPasswordRealm)
	form.Set("realm", "Other-DB")
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
		t.Fatalf("realm grant = %d %v", rec.Code, body)
	}
	// bob is not in the default directory.
	if rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")}); rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("default directory = %d %v", rec.Code, body)
	}
}

func TestPasswordGrantRejects(t *testing.T) {
	realm := func(r string) url.Values {
		v := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
		v.Set("grant_type", GrantPasswordRealm)
		if r != "" {
			v.Set("realm", r)
		}
		return v
	}
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"wrong password":    {pw("ropg", "ropg-secret", "alice@acme.test", "nope"), 400, "invalid_grant"},
		"unknown user":      {pw("ropg", "ropg-secret", "nobody@acme.test", "nope"), 400, "invalid_grant"},
		"blocked user":      {pw("ropg", "ropg-secret", "carol@acme.test", "carol password 1"), 400, "invalid_grant"},
		"missing password":  {pw("ropg", "ropg-secret", "alice@acme.test", ""), 400, "invalid_request"},
		"missing realm":     {realm(""), 400, "invalid_request"},
		"unknown realm":     {realm("Nope"), 400, "invalid_request"},
		"grant not allowed": {pw("code-web", "code-web-secret", "alice@acme.test", "alice password 1"), 403, "unauthorized_client"},
		"bad client secret": {pw("ropg", "wrong", "alice@acme.test", "alice password 1"), 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form})
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	// The wording is the same for unknown users and wrong passwords.
	f := newFixture(t)
	_, a := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	_, b := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "nobody@acme.test", "nope")})
	if a["error_description"] != b["error_description"] {
		t.Fatalf("descriptions differ: %v / %v", a, b)
	}
}

func TestPasswordGrantThrottle(t *testing.T) {
	f := newFixture(t)
	for range 3 {
		f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")})
	if rec.Code != 429 || body["error"] != "too_many_requests" {
		t.Fatalf("after 3 failures = %d %v", rec.Code, body)
	}
}

// A public client cannot pick its own throttling IP with auth0-forwarded-for.
func TestForwardedForOnlyForConfidentialClients(t *testing.T) {
	f := newFixture(t)
	f.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := range 2 {
		call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "nobody@acme.test", "nope"),
			header: map[string]string{"auth0-forwarded-for": fmt.Sprintf("10.0.0.%d", i)}}
		f.call(t, false, call)
	}
	call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 429 {
		t.Fatalf("public client escaped the IP limit: %d %v", rec.Code, body)
	}
	// A confidential client's auth0-forwarded-for is honoured: a fresh IP is not throttled.
	call = tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 200 {
		t.Fatalf("confidential client with forwarded IP = %d %v", rec.Code, body)
	}
}

// auth0-forwarded-for is used only when it is an IP address; otherwise a
// confidential client could mint a fresh throttle key per request.
func TestForwardedForMustBeAnIP(t *testing.T) {
	f := newFixture(t)
	f.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := range 2 {
		f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "nobody@acme.test", "nope"),
			header: map[string]string{"auth0-forwarded-for": fmt.Sprintf("not-an-ip-%d", i)}})
	}
	call := tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "not-an-ip-x"}}
	if rec, body := f.call(t, false, call); rec.Code != 429 {
		t.Fatalf("invalid forwarded IPs escaped the IP limit: %d %v", rec.Code, body)
	}
}

func legacyRealm(username, password string) url.Values {
	form := pw("ropg", "ropg-secret", username, password)
	form.Set("grant_type", GrantPasswordRealm)
	form.Set("realm", "Legacy-DB")
	return form
}

// auth0-auth-js getTokenByPassword sends grant_type=password with a realm.
func TestPasswordGrantHonoursRealm(t *testing.T) {
	call := func(f *fixture, username, password, realm string) (int, map[string]any) {
		extra := []string{}
		if realm != "" {
			extra = append(extra, "realm", realm)
		}
		rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", username, password, extra...)})
		return rec.Code, body
	}
	f := newFixture(t)
	// (a) bob exists only in Other-DB, a non-default connection.
	if code, body := call(f, "bob@acme.test", "bob password 12", "Other-DB"); code != 200 {
		t.Fatalf("realm = %d %v", code, body)
	} else if at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string)); at["gty"] != "password" {
		t.Fatalf("gty = %v", at["gty"])
	}
	// (b) a connection not enabled for the client fails like password-realm.
	_, viaPassword := call(f, "alice@acme.test", "alice password 1", "Unenabled-DB")
	realmForm := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "realm", "Unenabled-DB")
	realmForm.Set("grant_type", GrantPasswordRealm)
	rec, viaRealm := f.call(t, false, tokenCall{host: "acme.example.test", form: realmForm})
	if rec.Code != 400 || viaRealm["error"] != "invalid_request" || viaPassword["error"] != viaRealm["error"] || viaPassword["error_description"] != viaRealm["error_description"] {
		t.Fatalf("password = %v; password-realm = %d %v", viaPassword, rec.Code, viaRealm)
	}
	// An existing database connection that is not enabled for this client
	// (Other-DB is enabled only for ropg) gets the same answer.
	rec, notEnabled := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "bob@acme.test", "bob password 12", "realm", "Other-DB")})
	_, unknownRealm := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "bob@acme.test", "bob password 12", "realm", "Unenabled-DB")})
	if rec.Code != 400 || notEnabled["error"] != "invalid_request" || notEnabled["error_description"] != viaRealm["error_description"] || unknownRealm["error_description"] != viaRealm["error_description"] {
		t.Fatalf("not enabled = %d %v; unknown = %v; want description %v", rec.Code, notEnabled, unknownRealm, viaRealm["error_description"])
	}
	// (c) without a realm the default directory is used.
	if code, body := call(f, "bob@acme.test", "bob password 12", ""); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("no realm, bob = %d %v", code, body)
	}
	if code, body := call(f, "alice@acme.test", "alice password 1", ""); code != 200 {
		t.Fatalf("no realm, alice = %d %v", code, body)
	}
}

func TestPasswordGrantRealmWithoutDefaultDirectory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tn, err := f.st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	tn.DefaultDirectory = ""
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12", "realm", "Other-DB")})
	if rec.Code != 200 {
		t.Fatalf("realm without default directory = %d %v", rec.Code, body)
	}
	rec, body = f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")})
	if rec.Code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("no realm, no default = %d %v", rec.Code, body)
	}
}

func TestPasswordRealmGrantLegacy(t *testing.T) {
	f := newFixture(t)
	f.scripts.Funcs[store.ScriptLogin] = func(args []any) (any, error) {
		if args[0] == "dave@legacy.test" && args[1] == "dave legacy 1" {
			return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil
		}
		return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials}
	}
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "dave legacy 1")})
	if rec.Code != 200 {
		t.Fatalf("legacy grant = %d %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["sub"] != "auth0|42" {
		t.Fatalf("sub = %v", at["sub"])
	}
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "wrong")}); rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong password = %d %v", rec.Code, body)
	}
}

func TestPasswordRealmGrantLegacyErrors(t *testing.T) {
	f := newFixture(t)
	var scriptErr error
	f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) { return nil, scriptErr }
	scriptErr = &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "account suspended"}
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "pw")})
	if rec.Code != 401 || body["error"] != "unauthorized" || body["error_description"] != "account suspended" {
		t.Fatalf("unauthorized = %d %v", rec.Code, body)
	}
	scriptErr = customdb.ErrTimeout
	rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "pw")})
	if rec.Code != 500 || body["error"] != "server_error" {
		t.Fatalf("script error = %d %v", rec.Code, body)
	}
}

// An error the script raised counts against the throttles; a script that
// could not answer does not (D-0023).
func TestPasswordRealmGrantLegacyThrottle(t *testing.T) {
	t.Run("raised error counts", func(t *testing.T) {
		f := newFixture(t)
		f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
			return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "bad"}
		}
		for i := 0; i < 3; i++ { // the per-user limit is 3
			if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "guess")}); rec.Code != 500 {
				t.Fatalf("attempt %d = %d %v", i, rec.Code, body)
			}
		}
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "guess")}); rec.Code != 429 {
			t.Fatalf("attempt after the limit = %d %v", rec.Code, body)
		}
	})
	t.Run("timeout refunded", func(t *testing.T) {
		f := newFixture(t)
		timeout := true
		f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
			if timeout {
				return nil, customdb.ErrTimeout
			}
			return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil
		}
		for i := 0; i < 5; i++ {
			if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "pw")}); rec.Code != 500 {
				t.Fatalf("attempt %d = %d %v", i, rec.Code, body)
			}
		}
		timeout = false
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "pw")}); rec.Code != 200 {
			t.Fatalf("after timeouts = %d %v", rec.Code, body)
		}
	})
}

// useImportMode puts tenant's Legacy-DB connection in import mode.
func useImportMode(t *testing.T, st store.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	c, err := st.Connections().GetByName(ctx, tenantID, "Legacy-DB")
	if err != nil {
		t.Fatal(err)
	}
	c.ImportMode = true
	if err := st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

// In import mode the first grant migrates the user; later grants are
// checked locally.
func TestPasswordRealmGrantImport(t *testing.T) {
	f := newFixture(t)
	useImportMode(t, f.st, f.tenantID(t, "acme"))
	f.scripts.Funcs[store.ScriptLogin] = func(args []any) (any, error) {
		if args[0] == "dave@legacy.test" && args[1] == "dave legacy 1" {
			return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil
		}
		return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials}
	}
	for i := 0; i < 2; i++ {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "dave legacy 1")})
		if rec.Code != 200 {
			t.Fatalf("grant %d = %d %v", i, rec.Code, body)
		}
		at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
		if at["sub"] != "auth0|42" {
			t.Fatalf("sub = %v", at["sub"])
		}
	}
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "wrong")}); rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong password = %d %v", rec.Code, body)
	}
	if n := len(f.scripts.Requests()); n != 1 {
		t.Fatalf("script calls = %d, want 1", n)
	}
}

func (f *fixture) setUserPolicy(t *testing.T, audience, policy string) {
	t.Helper()
	ctx := context.Background()
	rs, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tenantID(t, "acme"), audience)
	if err != nil {
		t.Fatal(err)
	}
	rs.SubjectTypeAuthorization.User = policy
	if err := f.st.ResourceServers().Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) pwCall(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	return rec.Code, body
}

func TestPasswordGrantDenyAll(t *testing.T) {
	f := newFixture(t)
	code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://locked.test"))
	if code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("got %d %v", code, body)
	}
}

func TestPasswordGrantClientGrantCapsScopes(t *testing.T) {
	f := newFixture(t)
	code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://granted.test", "scope", "a b"))
	if code != 200 || body["scope"] != "a" {
		t.Fatalf("got %d %v", code, body)
	}
}

func TestPasswordGrantRequireClientGrantWithoutGrant(t *testing.T) {
	f := newFixture(t)
	code, body := f.pwCall(t, pw("other-ropg", "other-secret", "alice@acme.test", "alice password 1", "audience", "https://granted.test"))
	if code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("got %d %v", code, body)
	}
}

func TestRefreshGrantRechecksPolicy(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "ropg", []string{"a", "offline_access"}, "https://granted.test")
	if code, body := f.refresh(t, refreshForm("ropg", raw, "client_secret", "ropg-secret")); code != 200 {
		t.Fatalf("before = %d %v", code, body)
	}
	f.setUserPolicy(t, "https://granted.test", store.PolicyDenyAll)
	raw, _ = f.issueRefresh(t, "ropg", []string{"a", "offline_access"}, "https://granted.test")
	code, body := f.refresh(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
	if code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("got %d %v", code, body)
	}
}

func TestPasswordGrantThirdPartyRefusedBeforeLogin(t *testing.T) {
	var logs strings.Builder
	f := newFixture(t)
	f.h.Log = slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	c, err := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "ropg")
	if err != nil {
		t.Fatal(err)
	}
	c.IsFirstParty = false
	c.ThirdPartySecurityMode = store.SecurityModePermissive
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "wrong"))
		if code != 403 || body["error"] != "unauthorized_client" {
			t.Fatalf("got %d %v", code, body)
		}
	}
	if strings.Contains(logs.String(), "login failed") || strings.Contains(logs.String(), "password grant failed") {
		t.Fatalf("password was checked: %s", logs.String())
	}
	c.IsFirstParty = true
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	if code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")); code != 200 {
		t.Fatalf("throttle was charged: %d %v", code, body)
	}
}
