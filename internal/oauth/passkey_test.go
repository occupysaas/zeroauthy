package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

func nativeFixture(t *testing.T) (*fixture, *eventRecorder) {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	tn, _ := f.st.Tenants().Get(ctx, tid)
	tn.Domains = append(tn.Domains, "native.example.test", "other.example.test")
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	cfg, err := f.st.HostedLogins().Get(ctx, tid)
	if err != nil {
		cfg = &store.HostedLoginConfig{TenantID: tid}
	}
	cfg.Prompts = map[string]any{"universal_login_experience": "new", "identifier_first": true}
	if err := f.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	c, _ := f.st.Clients().Get(ctx, tid, "ropg")
	c.GrantTypes = append(c.GrantTypes, clientrules.GrantPasskey)
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	conn, _ := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	if conn.Extra == nil {
		conn.Extra = map[string]any{}
	}
	conn.Extra["authentication_methods"] = map[string]any{"passkey": map[string]any{"enabled": true}}
	if err := f.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	f.h.Passkeys = passkey.NewService(f.st, rpid.Policy{}, func() time.Time { return f.h.now() })
	capture := &eventRecorder{}
	f.h.Recorder = capture
	return f, capture
}
func (f *fixture) native(t *testing.T, path, host string, body any, form bool, nativeTenants ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var raw string
	ct := "application/json"
	if form {
		raw = body.(url.Values).Encode()
		ct = "application/x-www-form-urlencoded"
	} else {
		b, _ := json.Marshal(body)
		raw = string(b)
	}
	r := httptest.NewRequest("POST", "https://"+host+path, strings.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	name := "acme"
	if len(nativeTenants) > 0 {
		name = nativeTenants[0]
	}
	tid := f.tenantID(t, name)
	tn, _ := f.st.Tenants().Get(context.Background(), tid)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: host}))
	switch path {
	case "/passkey/register":
		f.h.PasskeyRegister(w, r)
	case "/passkey/challenge":
		f.h.PasskeyChallenge(w, r)
	default:
		f.h.OauthToken(w, r)
	}
	var b map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return w, b
}
func nativeBody() map[string]any {
	return map[string]any{"client_id": "ropg", "client_secret": "ropg-secret", "user_profile": map[string]any{"email": "native@acme.test", "name": "Native"}}
}
func nativeOptions(t *testing.T, b map[string]any) webauthn.CreationOptions {
	t.Helper()
	p := b["authn_params_public_key"].(map[string]any)
	u := p["user"].(map[string]any)
	rp := p["rp"].(map[string]any)
	ch, _ := base64.RawURLEncoding.DecodeString(p["challenge"].(string))
	handle, _ := base64.RawURLEncoding.DecodeString(u["id"].(string))
	return webauthn.CreationOptions{Challenge: ch, RPID: rp["id"].(string), UserID: handle, Algs: webauthn.DefaultAlgs}
}
func nativeToken(session string, raw []byte) url.Values {
	return url.Values{"grant_type": {clientrules.GrantPasskey}, "client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "auth_session": {session}, "authn_response": {string(raw)}, "scope": {"openid offline_access read:things"}}
}
func nativeSignup(t *testing.T, f *fixture) (*webauthntest.Authenticator, map[string]any) {
	t.Helper()
	w, b := f.native(t, "/passkey/register", "native.example.test", nativeBody(), false)
	if w.Code != 200 {
		t.Fatalf("register %d %v", w.Code, b)
	}
	d := webauthntest.New(webauthntest.Options{})
	raw := d.Create(nativeOptions(t, b), "https://native.example.test")
	w, b = f.native(t, "/oauth/token", "native.example.test", nativeToken(b["auth_session"].(string), raw), true)
	if w.Code != 200 {
		t.Fatalf("signup %d %v", w.Code, b)
	}
	return d, b
}
func nativeLogin(t *testing.T, f *fixture, d *webauthntest.Authenticator, origin string) (url.Values, map[string]any) {
	t.Helper()
	w, b := f.native(t, "/passkey/challenge", "native.example.test", map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}, false)
	if w.Code != 200 {
		t.Fatalf("challenge %d %v", w.Code, b)
	}
	p := b["authn_params_public_key"].(map[string]any)
	ch, _ := base64.RawURLEncoding.DecodeString(p["challenge"].(string))
	raw := d.Get(webauthn.RequestOptions{Challenge: ch, RPID: p["rpId"].(string)}, origin)
	return nativeToken(b["auth_session"].(string), raw), b
}

func TestPasskeyRegisterEndpoint(t *testing.T) {
	f, capture := nativeFixture(t)
	w, b := f.native(t, "/passkey/register", "native.example.test", nativeBody(), false)
	if w.Code != 200 {
		t.Fatalf("register %d %v", w.Code, b)
	}
	if len(b) != 2 {
		t.Fatal(b)
	}
	p := b["authn_params_public_key"].(map[string]any)
	if p["timeout"] != float64(60000) || p["attestation"] != "none" {
		t.Fatal(p)
	}
	sel := p["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["userVerification"] != "preferred" {
		t.Fatal(sel)
	}
	session := b["auth_session"].(string)
	row, err := f.st.MFA().GetChallenge(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(session), f.h.now())
	if err != nil || !row.ExpiresAt.Equal(f.h.now().Add(70*time.Second)) || strings.Contains(string(row.Binding), session) {
		t.Fatalf("session persistence %+v %v", row, err)
	}
	found := false
	for _, e := range capture.events {
		if e.Type == "passkey_challenge_started" && e.Details["purpose"] == "register" {
			found = true
		}
	}
	if !found {
		t.Fatal("no challenge event")
	}
	for _, tc := range []struct {
		name, host string
		change     func(map[string]any)
	}{
		{"canonical", "acme.example.test", func(b map[string]any) {}}, {"unknown profile", "", func(b map[string]any) { b["user_profile"].(map[string]any)["unknown"] = true }}, {"existing", "", func(b map[string]any) { b["user_profile"].(map[string]any)["email"] = "alice@acme.test" }}, {"name limit", "", func(b map[string]any) { b["user_profile"].(map[string]any)["name"] = strings.Repeat("n", 301) }}, {"given name limit", "", func(b map[string]any) { b["user_profile"].(map[string]any)["given_name"] = strings.Repeat("n", 151) }}, {"metadata limit", "", func(b map[string]any) {
			m := map[string]string{}
			for i := range 11 {
				m[fmt.Sprint(i)] = "v"
			}
			b["user_metadata"] = m
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := nativeFixture(t)
			body := nativeBody()
			tc.change(body)
			host := tc.host
			if host == "" {
				host = "native.example.test"
			}
			w, b := f.native(t, "/passkey/register", host, body, false)
			if w.Code != 400 || b["error"] != "invalid_request" {
				t.Fatalf("%d %v", w.Code, b)
			}
		})
	}
}
func TestPasskeyChallengeEndpoint(t *testing.T) {
	f, _ := nativeFixture(t)
	w, b := f.native(t, "/passkey/challenge", "native.example.test", map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}, false)
	if w.Code != 200 {
		t.Fatalf("%d %v", w.Code, b)
	}
	p := b["authn_params_public_key"].(map[string]any)
	if len(p) != 4 || p["timeout"] != float64(60000) || p["userVerification"] != "preferred" || p["rpId"] != "native.example.test" {
		t.Fatal(p)
	}
	c, _ := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "ropg")
	c.OrganizationUsage = store.OrgUsageRequire
	_ = f.st.Clients().Update(context.Background(), c)
	w, b = f.native(t, "/passkey/challenge", "native.example.test", map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}, false)
	if w.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("organization required %d %v", w.Code, b)
	}
}
func TestPasskeyGrant(t *testing.T) {
	f, capture := nativeFixture(t)
	d, b := nativeSignup(t, f)
	if b["refresh_token"] == nil || b["id_token"] == nil {
		t.Fatal(b)
	}
	form, _ := nativeLogin(t, f, d, "https://native.example.test")
	body := map[string]any{}
	for k := range form {
		body[k] = form.Get(k)
	}
	var raw any
	_ = json.Unmarshal([]byte(form.Get("authn_response")), &raw)
	body["authn_response"] = raw
	w, b := f.native(t, "/oauth/token", "native.example.test", body, false)
	if w.Code != 200 {
		t.Fatalf("object login %d %v", w.Code, b)
	}
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("reuse %d %v", w.Code, b)
	}
	ss, s, failed := false, false, false
	for _, e := range capture.events {
		if e.Type == "ss" && fmt.Sprint(e.Details["authentication_methods"]) == "[passkey]" {
			ss = true
		}
		if e.Type == "s" && strings.Contains(fmt.Sprint(e.Details["prompts"]), "phr") {
			s = true
		}
		if e.Type == "passkey_challenge_failed" {
			failed = true
		}
	}
	if !ss || !s || !failed {
		t.Fatalf("missing outcomes %+v", capture.events)
	}
}
func TestNativeOriginReplay(t *testing.T) {
	for _, tc := range []struct{ name, origin, host string }{{"other host", "https://native.example.test", "other.example.test"}, {"foreign origin", "https://evil.test", "native.example.test"}, {"port mismatch", "https://native.example.test:443", "native.example.test"}} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := nativeFixture(t)
			d, _ := nativeSignup(t, f)
			form, _ := nativeLogin(t, f, d, tc.origin)
			w, b := f.native(t, "/oauth/token", tc.host, form, true)
			if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("replay %d %v", w.Code, b)
			}
			w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("failed challenge retained %d %v", w.Code, b)
			}
		})
	}
}
func TestPasskeyGrantActions(t *testing.T) {
	f, _ := nativeFixture(t)
	a := actionstest.NewOffline(t, f.st, f.wrapper)
	tid := f.tenantID(t, "acme")
	a.Bind(t, tid, actions.TriggerPreUserRegistration, a.Deploy(t, tid, actions.TriggerPreUserRegistration, "native-pre", `exports.onExecutePreUserRegistration=(e,a)=>{if(JSON.stringify(e).includes('auth_session')||JSON.stringify(e).includes('attestationObject'))throw Error('proof leak'); a.user.setUserMetadata('pre_ran',true)}`))
	a.Bind(t, tid, actions.TriggerPostUserRegistration, a.Deploy(t, tid, actions.TriggerPostUserRegistration, "native-post", `exports.onExecutePostUserRegistration=()=>{}`))
	a.Bind(t, tid, actions.TriggerPostLogin, a.Deploy(t, tid, actions.TriggerPostLogin, "native-login", `exports.onExecutePostLogin=(e,a)=>{if(e.transaction.protocol!=='oauth2-webauthn'||!e.authentication.methods.some(x=>x.name==='passkey'))throw Error('wrong method');if(JSON.stringify(e.request).includes('auth_session')||JSON.stringify(e.request).includes('authn_response'))throw Error('proof leak');a.idToken.setCustomClaim('native_passkey',true)}`))
	f.h.Actions = a.Engine
	_, b := nativeSignup(t, f)
	claims, _ := verifyToken(t, f.keys, tid, b["id_token"].(string))
	if claims["native_passkey"] != true {
		t.Fatal(claims)
	}
	u, err := f.st.Users().FindByLogin(context.Background(), tid, "Username-Password-Authentication", "native@acme.test")
	if err != nil || u.UserMetadata["pre_ran"] != true {
		t.Fatalf("pre action %v %+v", err, u)
	}
	jobs, err := f.st.Actions().ClaimJobs(context.Background(), time.Now(), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("post action queue %v %v", jobs, err)
	}
}
func TestPasskeyGrantMFA(t *testing.T) {
	f, capture := nativeFixture(t)
	d, _ := nativeSignup(t, f)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	g, _ := f.st.MFA().GetGuardian(ctx, tid)
	g.Factors = map[string]bool{"otp": true, "recovery-code": true}
	g.Policies = []string{"all-applications"}
	if err := f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	mail := &mfaMail{}
	f.h.MFA = mfa.NewService(f.st, f.wrapper, mail, nil, f.h.Log, func() time.Time { return f.h.now() })
	c, _ := f.st.Clients().Get(ctx, tid, "ropg")
	c.GrantTypes = append(c.GrantTypes, otpGrant)
	_ = f.st.Clients().Update(ctx, c)
	form, _ := nativeLogin(t, f, d, "https://native.example.test")
	w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 403 || b["error"] != "mfa_required" {
		t.Fatalf("%d %v", w.Code, b)
	}
	tok := b["mfa_token"].(string)
	r := httptest.NewRequest("POST", "https://native.example.test/mfa/associate", strings.NewReader(`{"authenticator_types":["otp"]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	tn, _ := f.st.Tenants().Get(ctx, tid)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: "native.example.test"}))
	rec := httptest.NewRecorder()
	f.h.MFAAssociate(rec, r)
	var association map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &association)
	if rec.Code != 200 {
		t.Fatalf("associate %d %v", rec.Code, association)
	}
	secret := association["secret"].(string)
	w, b = f.native(t, "/oauth/token", "native.example.test", mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now())), true)
	if w.Code != 200 {
		t.Fatalf("MFA proof %d %v", w.Code, b)
	}
	found := false
	for _, e := range capture.events {
		if e.Type == "sepkotpft" {
			found = true
		}
	}
	if !found {
		t.Fatalf("MFA success event %+v", capture.events)
	}
}

type nativeUnavailable struct{ store.Store }

func (nativeUnavailable) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
func TestPasskeyRegisterEndpointPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		change func(*fixture, map[string]any)
	}{
		{"bad secret", 401, "invalid_client", func(f *fixture, b map[string]any) { b["client_secret"] = "bad" }},
		{"third party", 400, "invalid_request", func(f *fixture, b map[string]any) {
			c, _ := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "ropg")
			c.IsFirstParty = false
			_ = f.st.Clients().Update(context.Background(), c)
		}},
		{"missing grant", 400, "invalid_request", func(f *fixture, b map[string]any) {
			c, _ := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "ropg")
			c.GrantTypes = []string{"password"}
			_ = f.st.Clients().Update(context.Background(), c)
		}},
		{"unavailable", 404, "not_found", func(f *fixture, b map[string]any) { f.h.Store = nativeUnavailable{f.st} }},
		{"unavailable strict RP policy", 404, "not_found", func(f *fixture, b map[string]any) {
			f.h.Store = nativeUnavailable{f.st}
			f.h.Passkeys.RPID.RestrictShared = true
		}},
		{"ineffective", 404, "not_found", func(f *fixture, b map[string]any) {
			conn, _ := f.st.Connections().GetByName(context.Background(), f.tenantID(t, "acme"), "Username-Password-Authentication")
			conn.Extra = nil
			_ = f.st.Connections().Update(context.Background(), conn)
		}},
		{"invalid RP", 400, "invalid_request", func(f *fixture, b map[string]any) {
			tn, _ := f.st.Tenants().Get(context.Background(), f.tenantID(t, "acme"))
			tn.DomainRPIDs = map[string]string{"native.example.test": "foreign.test"}
			if err := f.st.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
		}},
		{"verification", 400, "invalid_request", func(f *fixture, b map[string]any) {
			conn, _ := f.st.Connections().GetByName(context.Background(), f.tenantID(t, "acme"), "Username-Password-Authentication")
			conn.Extra["attributes"] = map[string]any{"email": map[string]any{"signup": map[string]any{"verification": map[string]any{"active": true}}}}
			_ = f.st.Connections().Update(context.Background(), conn)
		}},
		{"metadata scalar", 400, "invalid_request", func(f *fixture, b map[string]any) { b["user_metadata"] = map[string]any{"a": true} }},
		{"no defaultable realm", 400, "invalid_request", func(f *fixture, b map[string]any) {
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			tn, _ := f.st.Tenants().Get(ctx, tid)
			tn.DefaultDirectory = ""
			_ = f.st.Tenants().Update(ctx, tn)
			conn, _ := f.st.Connections().GetByName(ctx, tid, "Other-DB")
			conn.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}
			_ = f.st.Connections().Update(ctx, conn)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := nativeFixture(t)
			body := nativeBody()
			tc.change(f, body)
			w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
			if w.Code != tc.status || b["error"] != tc.code {
				t.Fatalf("%d %v", w.Code, b)
			}
			if w.Code == 404 && len(b) != 1 {
				t.Fatal(b)
			}
		})
	}
}
func TestPasskeyRegisterBudgetBeforeExistence(t *testing.T) {
	f, _ := nativeFixture(t)
	setProtectionLimits(t, f.st, 3, 30, 1)
	body := nativeBody()
	body["user_profile"].(map[string]any)["email"] = "alice@acme.test"
	w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
	if w.Code != 400 {
		t.Fatalf("first existence %d %v", w.Code, b)
	}
	w, b = f.native(t, "/passkey/register", "native.example.test", body, false)
	if w.Code != 429 || b["error"] != "too_many_requests" {
		t.Fatalf("budget %d %v", w.Code, b)
	}
}
func TestPasskeyGrantBindingsAndFailures(t *testing.T) {
	for _, kind := range []string{"expired", "client", "realm", "malformed", "type", "signature", "blocked"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := nativeFixture(t)
			d, _ := nativeSignup(t, f)
			form, _ := nativeLogin(t, f, d, "https://native.example.test")
			switch kind {
			case "expired":
				f.h.Now = func() time.Time { return fixedNow().Add(71 * time.Second) }
			case "client":
				c, _ := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "other-ropg")
				c.GrantTypes = append(c.GrantTypes, clientrules.GrantPasskey)
				_ = f.st.Clients().Update(context.Background(), c)
				form.Set("client_id", "other-ropg")
				form.Set("client_secret", "other-secret")
			case "realm":
				form.Set("realm", "Other-DB")
			case "malformed":
				form.Set("authn_response", "not-json")
			case "type":
				form.Set("authn_response", `{"type":"wrong"}`)
			case "signature":
				var cred map[string]any
				_ = json.Unmarshal([]byte(form.Get("authn_response")), &cred)
				cred["response"].(map[string]any)["signature"] = "AAAA"
				raw, _ := json.Marshal(cred)
				form.Set("authn_response", string(raw))
			case "blocked":
				u, _ := f.st.Users().FindByLogin(context.Background(), f.tenantID(t, "acme"), "Username-Password-Authentication", "native@acme.test")
				u.Blocked = true
				_ = f.st.Users().Update(context.Background(), u)
			}
			w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("%d %v", w.Code, b)
			}
			want := "Passkey authentication failed."
			if kind == "blocked" {
				want = "user is blocked"
			}
			if b["error_description"] != want {
				t.Fatal(b)
			}
			form.Set("client_id", "ropg")
			form.Set("client_secret", "ropg-secret")
			form.Del("realm")
			w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 400 || b["error_description"] != "Passkey authentication failed." {
				t.Fatalf("challenge not consumed %d %v", w.Code, b)
			}
		})
	}
}
func TestNativeOriginAndroid(t *testing.T) {
	f, _ := nativeFixture(t)
	ctx := context.Background()
	c, _ := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "ropg")
	c.Mobile = &store.ClientMobile{Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{strings.Repeat("AB:", 31) + "AB"}}}
	_ = f.st.Clients().Update(ctx, c)
	d, _ := nativeSignup(t, f)
	form, _ := nativeLogin(t, f, d, "android:apk-key-hash:q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s")
	w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 200 {
		t.Fatalf("Android origin %d %v", w.Code, b)
	}
}
func TestPasskeyRegisterFormAndObjectGrant(t *testing.T) {
	f, _ := nativeFixture(t)
	profile, _ := json.Marshal(nativeBody()["user_profile"])
	w, b := f.native(t, "/passkey/register", "native.example.test", url.Values{"client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "user_profile": {string(profile)}}, true)
	if w.Code != 200 {
		t.Fatalf("form options %d %v", w.Code, b)
	}
	d := webauthntest.New(webauthntest.Options{})
	raw := d.Create(nativeOptions(t, b), "https://native.example.test")
	form := nativeToken(b["auth_session"].(string), raw)
	body := map[string]any{}
	for k := range form {
		body[k] = form.Get(k)
	}
	var credential any
	_ = json.Unmarshal(raw, &credential)
	body["authn_response"] = credential
	w, b = f.native(t, "/oauth/token", "native.example.test", body, false)
	if w.Code != 200 {
		t.Fatalf("object registration %d %v", w.Code, b)
	}
}
func TestPasskeyChallengeFailureBudget(t *testing.T) {
	f, _ := nativeFixture(t)
	setProtectionLimits(t, f.st, 3, 1, 50)
	form := nativeToken("unknown-session", []byte(`{}`))
	w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 400 {
		t.Fatalf("first %d %v", w.Code, b)
	}
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 429 {
		t.Fatalf("missing session bypassed failure budget %d %v", w.Code, b)
	}
}

func TestPasskeyGrantMFASuccessCodes(t *testing.T) {
	for _, passkeyFirst := range []bool{false, true} {
		for _, factor := range []string{"otp", "email", "recovery-code"} {
			t.Run(fmt.Sprintf("passkey_%v/%s", passkeyFirst, factor), func(t *testing.T) {
				f, capture := nativeFixture(t)
				ctx := context.Background()
				tid := f.tenantID(t, "acme")
				var device *webauthntest.Authenticator
				uid := f.aliceID(t)
				if passkeyFirst {
					device, _ = nativeSignup(t, f)
					u, _ := f.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "native@acme.test")
					uid = u.UserID
					if factor == "email" {
						u.EmailVerified = true
						if e := f.st.Users().Update(ctx, u); e != nil {
							t.Fatal(e)
						}
					}
				}
				g, _ := f.st.MFA().GetGuardian(ctx, tid)
				g.Factors = map[string]bool{"otp": true, "email": true, "recovery-code": true}
				g.Policies = []string{"all-applications"}
				if e := f.st.MFA().PutGuardian(ctx, g, g.Version); e != nil {
					t.Fatal(e)
				}
				mail := &mfaMail{}
				f.h.MFA = mfa.NewService(f.st, f.wrapper, mail, nil, f.h.Log, func() time.Time { return f.h.now() })
				enrollFactor := factor
				if factor == "recovery-code" {
					enrollFactor = "otp"
				}
				enrollment, e := f.h.MFA.BeginEnroll(ctx, tid, uid, enrollFactor, "")
				if e != nil {
					t.Fatal(e)
				}
				proof := mail.code
				if enrollFactor == "otp" {
					proof = otpAt(enrollment.Secret, f.h.now())
				}
				confirmed, e := f.h.MFA.ConfirmEnroll(ctx, tid, uid, enrollment, mfa.Proof{Code: proof})
				if e != nil {
					t.Fatal(e)
				}
				f.h.Now = func() time.Time { return fixedNow().Add(31 * time.Second) }
				c, _ := f.st.Clients().Get(ctx, tid, "ropg")
				c.GrantTypes = append(c.GrantTypes, otpGrant, oobGrant, recoveryGrant)
				_ = f.st.Clients().Update(ctx, c)
				var form url.Values
				if passkeyFirst {
					form, _ = nativeLogin(t, f, device, "https://native.example.test")
				} else {
					form = pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
				}
				w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
				if w.Code != 403 || b["error"] != "mfa_required" {
					t.Fatalf("first factor %d %v", w.Code, b)
				}
				tok := b["mfa_token"].(string)
				code := "seotpft"
				switch factor {
				case "otp":
					form = mfaForm(otpGrant, tok, "otp", otpAt(enrollment.Secret, f.h.now()))
				case "email":
					challenge, e := f.h.MFA.BeginChallenge(ctx, tid, uid, enrollment.AuthenticatorID, "")
					if e != nil {
						t.Fatal(e)
					}
					form = mfaForm(oobGrant, tok, "oob_code", challenge.ID)
					form.Set("binding_code", mail.code)
					code = "seoobft"
				case "recovery-code":
					form = mfaForm(recoveryGrant, tok, "recovery_code", confirmed.RecoveryCode)
					code = "sercft"
				}
				if passkeyFirst {
					switch code {
					case "seotpft":
						code = "sepkotpft"
					case "seoobft":
						code = "sepkoobft"
					case "sercft":
						code = "sepkrcft"
					}
				}
				w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
				if w.Code != 200 {
					t.Fatalf("continuation %d %v", w.Code, b)
				}
				found := false
				for _, e := range capture.events {
					if e.Type == code {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %s in %+v", code, capture.events)
				}
			})
		}
	}
}

// Object and form encodings must reach the same verifier without changing the
// precedence of differently cased credential fields during reserialization.
func TestPasskeyGrantResponseEncoding(t *testing.T) {
	for _, object := range []bool{false, true} {
		t.Run(fmt.Sprint(object), func(t *testing.T) {
			f, _ := nativeFixture(t)
			d, _ := nativeSignup(t, f)
			form, _ := nativeLogin(t, f, d, "https://native.example.test")
			raw := strings.Replace(form.Get("authn_response"), `"type":"public-key"`, `"type":"wrong","Type":"public-key"`, 1)
			if raw == form.Get("authn_response") {
				t.Fatal("test credential has no type")
			}
			form.Set("authn_response", raw)
			var w *httptest.ResponseRecorder
			var b map[string]any
			if object {
				body := map[string]any{}
				for k := range form {
					body[k] = form.Get(k)
				}
				body["authn_response"] = json.RawMessage(raw)
				w, b = f.native(t, "/oauth/token", "native.example.test", body, false)
			} else {
				w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			}
			if w.Code != 200 {
				t.Fatalf("credential interpretation changed with encoding %d %v", w.Code, b)
			}
		})
	}
}

func TestPasskeyGrantOrganization(t *testing.T) {
	f, _ := nativeFixture(t)
	ctx := context.Background()
	of := organizationFixtureWith(t, f)
	f.setOrgUsage(t, "ropg", store.OrgUsageRequire, "no_prompt")
	body := nativeBody()
	body["organization"] = of.org.ID
	w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
	if w.Code != 200 {
		t.Fatalf("org options %d %v", w.Code, b)
	}
	d := webauthntest.New(webauthntest.Options{})
	raw := d.Create(nativeOptions(t, b), "https://native.example.test")
	form := nativeToken(b["auth_session"].(string), raw)
	form.Set("organization", of.org.ID)
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 200 {
		t.Fatalf("org signup %d %v", w.Code, b)
	}
	claims, _ := verifyToken(t, f.keys, of.tid, b["id_token"].(string))
	if claims["org_id"] != of.org.ID {
		t.Fatal(claims)
	}
	rt, e := f.st.RefreshTokens().GetByTokenHash(ctx, of.tid, secrets.HashToken(b["refresh_token"].(string)))
	if e != nil || rt.OrganizationID != of.org.ID || rt.OrganizationConnectionID != of.connID {
		t.Fatalf("org refresh %+v %v", rt, e)
	}
	member, e := f.st.Organizations().IsMember(ctx, of.tid, of.org.ID, rt.UserID)
	if e != nil || !member {
		t.Fatalf("auto membership %v %v", member, e)
	}
	// Removing the bound organization consumes a new registration session.
	body["user_profile"].(map[string]any)["email"] = "other-native@acme.test"
	w, b = f.native(t, "/passkey/register", "native.example.test", body, false)
	if w.Code != 200 {
		t.Fatalf("other options %d %v", w.Code, b)
	}
	raw = d.Create(nativeOptions(t, b), "https://native.example.test")
	form = nativeToken(b["auth_session"].(string), raw)
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("missing org %d %v", w.Code, b)
	}
	form.Set("organization", of.org.ID)
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("org mismatch retained session %d %v", w.Code, b)
	}
}

type nativeSignupFailureStore struct{ store.Store }

func (s nativeSignupFailureStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(nativeSignupFailureStore{tx}) })
}
func (s nativeSignupFailureStore) WebAuthn() store.WebAuthn {
	return nativeSignupFailureWebAuthn{s.Store.WebAuthn()}
}

type nativeSignupFailureWebAuthn struct{ store.WebAuthn }

func (s nativeSignupFailureWebAuthn) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	if err := s.WebAuthn.CreateUserWithPasskey(ctx, u, a); err != nil {
		return err
	}
	return store.ErrConflict
}
func TestPasskeyGrantAtomicSignupEvents(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f, _ := nativeFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			base := f.st
			var rawStore store.Store = base
			if fail {
				rawStore = nativeSignupFailureStore{base}
			}
			wrapped := events.Wrap(rawStore, events.Config{})
			f.h.Store = wrapped
			f.h.Database.Store = wrapped
			f.h.Passkeys.Store = wrapped
			w, b := f.native(t, "/passkey/register", "native.example.test", nativeBody(), false)
			if w.Code != 200 {
				t.Fatalf("options %d %v", w.Code, b)
			}
			d := webauthntest.New(webauthntest.Options{})
			raw := d.Create(nativeOptions(t, b), "https://native.example.test")
			w, b = f.native(t, "/oauth/token", "native.example.test", nativeToken(b["auth_session"].(string), raw), true)
			u, err := base.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "native@acme.test")
			outbox, e := base.Events().EventsAfter(ctx, tid, 0, []string{"user.created"}, 100, time.Now().Add(time.Hour))
			if e != nil {
				t.Fatal(e)
			}
			if fail {
				if w.Code != 400 || !errors.Is(err, store.ErrNotFound) || len(outbox) != 0 {
					t.Fatalf("atomic rollback %d %v user=%+v err=%v events=%v", w.Code, b, u, err, outbox)
				}
				return
			}
			if w.Code != 200 || err != nil || len(outbox) != 1 {
				t.Fatalf("signup event %d %v %v %v", w.Code, b, err, outbox)
			}
			methods, e := base.MFA().ListAuthenticators(ctx, tid, u.UserID)
			if e != nil || len(methods) != 1 || methods[0].Type != "passkey" || u.Identities[0].PasswordHash != "" {
				t.Fatalf("atomic credential %+v %v", methods, e)
			}
			eventJSON, _ := json.Marshal(outbox)
			if strings.Contains(string(eventJSON), "user_handle") || strings.Contains(string(eventJSON), "public_key") || strings.Contains(string(eventJSON), "auth_session") {
				t.Fatal("credential projected into event")
			}
		})
	}
}
func TestPasskeyGrantBruteForceProtection(t *testing.T) {
	f, _ := nativeFixture(t)
	d, _ := nativeSignup(t, f)
	for range 3 {
		w, b := f.native(t, "/oauth/token", "native.example.test", pw("ropg", "ropg-secret", "native@acme.test", "wrong password"), true)
		if w.Code != 403 || b["error"] != "invalid_grant" {
			t.Fatalf("password failure %d %v", w.Code, b)
		}
	}
	form, _ := nativeLogin(t, f, d, "https://native.example.test")
	w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 429 {
		t.Fatalf("passkey bypassed brute force %d %v", w.Code, b)
	}
}

func TestPasskeyRegisterJSONTypes(t *testing.T) {
	for _, field := range []string{"user_profile", "user_metadata"} {
		for _, value := range []any{`{"email":"type@acme.test"}`, true, 42, nil, []any{}} {
			t.Run(fmt.Sprintf("%s/%T", field, value), func(t *testing.T) {
				f, _ := nativeFixture(t)
				body := nativeBody()
				body[field] = value
				w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
				if w.Code != 400 || b["error"] != "invalid_request" {
					t.Fatalf("JSON object required %d %v", w.Code, b)
				}
			})
		}
	}
}
func TestNativeOriginRegistrationReplay(t *testing.T) {
	for _, other := range []bool{false, true} {
		t.Run(fmt.Sprint(other), func(t *testing.T) {
			f, _ := nativeFixture(t)
			ctx := context.Background()
			tn, _ := f.st.Tenants().Get(ctx, f.tenantID(t, "acme"))
			tn.DomainRPIDs = map[string]string{"native.example.test": "example.test", "other.example.test": "example.test"}
			if e := f.st.Tenants().Update(ctx, tn); e != nil {
				t.Fatal(e)
			}
			w, b := f.native(t, "/passkey/register", "native.example.test", nativeBody(), false)
			if w.Code != 200 {
				t.Fatalf("options %d %v", w.Code, b)
			}
			origin := "https://unlisted.example.test"
			host := "native.example.test"
			if other {
				origin = "https://native.example.test"
				host = "other.example.test"
			}
			d := webauthntest.New(webauthntest.Options{})
			raw := d.Create(nativeOptions(t, b), origin)
			session := b["auth_session"].(string)
			w, b = f.native(t, "/oauth/token", host, nativeToken(session, raw), true)
			if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("registration replay %d %v", w.Code, b)
			}
			w, b = f.native(t, "/oauth/token", "native.example.test", nativeToken(session, raw), true)
			if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("registration retained %d %v", w.Code, b)
			}
		})
	}
}

func TestNativeOriginRegistrationTenantReplay(t *testing.T) {
	f, _ := nativeFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "globex")
	c, _ := f.st.Clients().Get(ctx, tid, "globex-web")
	c.GrantTypes = append(c.GrantTypes, clientrules.GrantPasskey)
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	w, b := f.native(t, "/passkey/register", "native.example.test", nativeBody(), false)
	if w.Code != 200 {
		t.Fatalf("options %d %v", w.Code, b)
	}
	d := webauthntest.New(webauthntest.Options{})
	raw := d.Create(nativeOptions(t, b), "https://native.example.test")
	form := nativeToken(b["auth_session"].(string), raw)
	form.Set("client_id", "globex-web")
	form.Set("client_secret", "globex-web-secret")
	w, b = f.native(t, "/oauth/token", "globex.example.test", form, true, "globex")
	if w.Code != 400 || b["error"] != "invalid_grant" || b["error_description"] != "Passkey authentication failed." {
		t.Fatalf("tenant replay %d %v", w.Code, b)
	}
	form.Set("client_id", "ropg")
	form.Set("client_secret", "ropg-secret")
	w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
	if w.Code != 200 {
		t.Fatalf("foreign tenant altered owner's ceremony %d %v", w.Code, b)
	}
}
func TestPasskeyRegisterIdentifierExistence(t *testing.T) {
	for _, kind := range []string{"username", "phone_number"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := nativeFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			conn, _ := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
			conn.Extra["attributes"] = map[string]any{kind: map[string]any{"identifier": map[string]any{"active": true}, "signup": map[string]any{"verification": map[string]any{"active": false}}}}
			u, _ := f.st.Users().Get(ctx, tid, f.aliceID(t))
			body := nativeBody()
			if kind == "username" {
				conn.RequiresUsername = true
				u.Username = "alice_name"
				body["user_profile"].(map[string]any)[kind] = u.Username
			} else {
				u.PhoneNumber = "+12025550123"
				body["user_profile"].(map[string]any)[kind] = u.PhoneNumber
			}
			if e := f.st.Users().Update(ctx, u); e != nil {
				t.Fatal(e)
			}
			if e := f.st.Connections().Update(ctx, conn); e != nil {
				t.Fatal(e)
			}
			w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
			if w.Code != 400 || b["error"] != "invalid_request" || b["error_description"] != "The user already exists" {
				t.Fatalf("identifier existence %d %v", w.Code, b)
			}
		})
	}
}

func TestPasskeyRegisterEndpointBodyLimit(t *testing.T) {
	f, _ := nativeFixture(t)
	body := nativeBody()
	body["oversized"] = strings.Repeat("x", 65<<10)
	w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
	if w.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("body limit %d %v", w.Code, b)
	}
}
func TestPasskeyChallengeOnlyRealmDefault(t *testing.T) {
	f, _ := nativeFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	tn, _ := f.st.Tenants().Get(ctx, tid)
	tn.DefaultDirectory = ""
	if e := f.st.Tenants().Update(ctx, tn); e != nil {
		t.Fatal(e)
	}
	w, b := f.native(t, "/passkey/challenge", "native.example.test", map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}, false)
	if w.Code != 200 {
		t.Fatalf("sole realm default %d %v", w.Code, b)
	}
}

// An organization-required client must accept only its own sealed, organization-
// bound passkey continuation, while rechecking current membership and app access.
func TestPasskeyGrantMFARequiredOrganization(t *testing.T) {
	for _, kind := range []string{"success", "success_oob", "success_recovery", "membership_revoked", "connection_disabled", "client_access_revoked", "client_usage_denied", "organization_deleted", "no_organization", "password", "other_client"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := nativeFixture(t)
			device, _ := nativeSignup(t, f)
			ctx := context.Background()
			of := organizationFixtureWith(t, f)
			u, err := f.st.Users().FindByLogin(ctx, of.tid, "Username-Password-Authentication", "native@acme.test")
			if err != nil {
				t.Fatal(err)
			}
			if err = f.st.Organizations().AddMembers(ctx, of.tid, of.org.ID, []string{u.UserID}); err != nil {
				t.Fatal(err)
			}
			of.org.IsAppEntitlementActive = true
			if err = f.st.Organizations().Update(ctx, of.org); err != nil {
				t.Fatal(err)
			}
			if err = f.st.OrganizationsII().PutClients(ctx, of.tid, of.org.ID, []store.OrganizationClient{{ClientID: "ropg", UseForMemberAccess: true}}); err != nil {
				t.Fatal(err)
			}
			g, _ := f.st.MFA().GetGuardian(ctx, of.tid)
			g.Factors = map[string]bool{"otp": true, "email": true, "recovery-code": true}
			g.Policies = []string{"all-applications"}
			if err = f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
				t.Fatal(err)
			}
			mail := &mfaMail{}
			f.h.MFA = mfa.NewService(f.st, f.wrapper, mail, nil, f.h.Log, func() time.Time { return f.h.now() })
			uid := u.UserID
			if kind == "password" {
				uid = f.aliceID(t)
			}
			factor := "otp"
			if kind == "success_oob" {
				factor = "email"
				u.EmailVerified = true
				if err = f.st.Users().Update(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			enrollment, err := f.h.MFA.BeginEnroll(ctx, of.tid, uid, factor, "")
			if err != nil {
				t.Fatal(err)
			}
			proof := mail.code
			if factor == "otp" {
				proof = otpAt(enrollment.Secret, f.h.now())
			}
			confirmed, err := f.h.MFA.ConfirmEnroll(ctx, of.tid, uid, enrollment, mfa.Proof{Code: proof})
			if err != nil {
				t.Fatal(err)
			}
			f.h.Now = func() time.Time { return fixedNow().Add(31 * time.Second) }
			for _, id := range []string{"ropg", "other-ropg"} {
				c, _ := f.st.Clients().Get(ctx, of.tid, id)
				c.GrantTypes = append(c.GrantTypes, otpGrant, oobGrant, recoveryGrant)
				c.OrganizationUsage = store.OrgUsageAllow
				if err = f.st.Clients().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			bound := kind != "no_organization" && kind != "password"
			var form url.Values
			if kind == "password" {
				form = pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
			} else {
				body := map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}
				if bound {
					f.setOrgUsage(t, "ropg", store.OrgUsageRequire, "no_prompt")
					body["organization"] = of.org.ID
				}
				w, b := f.native(t, "/passkey/challenge", "native.example.test", body, false)
				if w.Code != 200 {
					t.Fatalf("challenge %d %v", w.Code, b)
				}
				opts := b["authn_params_public_key"].(map[string]any)
				challenge, _ := base64.RawURLEncoding.DecodeString(opts["challenge"].(string))
				raw := device.Get(webauthn.RequestOptions{Challenge: challenge, RPID: opts["rpId"].(string)}, "https://native.example.test")
				form = nativeToken(b["auth_session"].(string), raw)
				if bound {
					form.Set("organization", of.org.ID)
				}
			}
			w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 403 || b["error"] != "mfa_required" {
				t.Fatalf("first factor %d %v", w.Code, b)
			}
			tok := b["mfa_token"].(string)
			f.setOrgUsage(t, "ropg", store.OrgUsageRequire, "no_prompt")
			switch kind {
			case "membership_revoked":
				err = f.st.Organizations().RemoveMembers(ctx, of.tid, of.org.ID, []string{uid})
			case "connection_disabled":
				link, e := f.st.Organizations().GetConnection(ctx, of.tid, of.org.ID, of.connID)
				if e != nil {
					t.Fatal(e)
				}
				link.IsEnabledSet, link.IsEnabled = true, false
				err = f.st.Organizations().PutConnection(ctx, *link, false)
			case "client_usage_denied":
				f.setOrgUsage(t, "ropg", store.OrgUsageDeny, "no_prompt")
			case "organization_deleted":
				err = f.st.Organizations().Delete(ctx, of.tid, of.org.ID)
			case "client_access_revoked":
				err = f.st.OrganizationsII().DeleteClients(ctx, of.tid, of.org.ID, []string{"ropg"})
			}
			if err != nil {
				t.Fatal(err)
			}
			form = mfaForm(otpGrant, tok, "otp", otpAt(enrollment.Secret, f.h.now()))
			switch kind {
			case "success_oob":
				challenge, e := f.h.MFA.BeginChallenge(ctx, of.tid, uid, enrollment.AuthenticatorID, "")
				if e != nil {
					t.Fatal(e)
				}
				form = mfaForm(oobGrant, tok, "oob_code", challenge.ID)
				form.Set("binding_code", mail.code)
			case "success_recovery":
				form = mfaForm(recoveryGrant, tok, "recovery_code", confirmed.RecoveryCode)
			}
			// A public organization parameter cannot supply missing trusted context.
			form.Set("organization", of.org.ID)
			if kind == "other_client" {
				f.setOrgUsage(t, "other-ropg", store.OrgUsageRequire, "no_prompt")
				form.Set("client_id", "other-ropg")
				form.Set("client_secret", "other-secret")
			}
			w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			if !strings.HasPrefix(kind, "success") {
				code := "invalid_grant"
				if !bound || kind == "other_client" {
					code = "unauthorized_client"
				}
				status := 400
				if code == "unauthorized_client" {
					status = 403
				}
				if w.Code != status || b["error"] != code || b["access_token"] != nil {
					t.Fatalf("guard %d %v", w.Code, b)
				}
				return
			}
			if w.Code != 200 {
				t.Fatalf("continuation %d %v", w.Code, b)
			}
			claims, _ := verifyToken(t, f.keys, of.tid, b["id_token"].(string))
			if claims["org_id"] != of.org.ID {
				t.Fatalf("organization claims %v", claims)
			}
			w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 403 || b["error"] != "unauthorized_client" || b["access_token"] != nil {
				t.Fatalf("replay %d %v", w.Code, b)
			}
		})
	}
}

// Without webauthn.v1 the native endpoints answer 404 on every host,
// including the canonical host that would otherwise get a 400 for lacking a
// custom domain: an old plugin must look exactly like "no passkey API".
func TestPasskeyEndpointsUnavailableOnCanonicalHost(t *testing.T) {
	for _, path := range []string{"/passkey/register", "/passkey/challenge"} {
		f, _ := nativeFixture(t)
		f.h.Store = nativeUnavailable{f.st}
		w, b := f.native(t, path, "acme.example.test", nativeBody(), false)
		if w.Code != 404 || b["error"] != "not_found" || len(b) != 1 {
			t.Fatalf("%s: %d %v", path, w.Code, b)
		}
	}
}
