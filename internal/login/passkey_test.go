package login

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

type passkeyPage struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"publicKey"`
	Mediation   string          `json:"mediation"`
}

func readPasskeyPage(t *testing.T, rec *httptest.ResponseRecorder) passkeyPage {
	t.Helper()
	m := regexp.MustCompile(`(?s)<script[^>]*id="za-webauthn"[^>]*>(.*?)</script>`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("missing options: %d %s", rec.Code, rec.Body)
	}
	var p passkeyPage
	if err := json.Unmarshal([]byte(m[1]), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func passkeyEnv(t *testing.T) (*env, *store.User, *webauthntest.Authenticator, *store.Authenticator) {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	tn, _ := e.st.Tenants().GetByName(ctx, "acme")
	cfg, _ := e.st.HostedLogins().Get(ctx, tn.ID)
	cfg.Prompts = map[string]any{"universal_login_experience": "new", "identifier_first": true}
	if err := e.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	conn, _ := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	conn.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}
	if err := e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	e.h.Passkeys = passkey.NewService(e.st, rpid.Policy{}, fixedNow)
	// Exercise the same HTTP dispatch and tenant middleware as the hosted fixtures.
	original := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/u/login/passkey" {
			tenantHandler(e.h.LoginPasskeyPost, e.st).ServeHTTP(w, r)
			return
		}
		original.ServeHTTP(w, r)
	})
	u, _ := e.st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	b := passkey.Binding{Purpose: passkey.PasskeyRegister, RPID: "acme.example.test", Origins: []string{"https://acme.example.test"}, TxnID: "enroll", CookieHash: "enroll-cookie", UserID: u.UserID, ClientID: "spa", Realm: conn.Name}
	issued, err := e.h.Passkeys.Issue(ctx, tn.ID, b, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := e.h.Passkeys.CreationOptions(ctx, tn.ID, u, passkey.UserDisplay{}, b.RPID, passkey.Progressive, issued.Challenge, issued.UserHandle, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	device := webauthntest.New(webauthntest.Options{})
	raw := device.Create(opts, b.Origins[0])
	taken, err := e.h.Passkeys.Take(ctx, tn.ID, issued.ID, b)
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.h.Passkeys.Enroll(ctx, tn.ID, u, u.Identities[0].UserID, raw, taken, "Test Browser")
	if err != nil {
		t.Fatal(err)
	}
	return e, u, device, a
}
func passkeyForm(t *testing.T, b *browser, device *webauthntest.Authenticator, extra ...string) (url.Values, string) {
	t.Helper()
	page, state, csrf := b.begin(t, extra...)
	p := readPasskeyPage(t, page)
	var o struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		Allow     []any  `json:"allowCredentials"`
	}
	if err := json.Unmarshal(p.Options, &o); err != nil {
		t.Fatal(err)
	}
	if len(o.Allow) != 0 {
		t.Fatal("discoverable options enumerate credentials")
	}
	ch, _ := base64.RawURLEncoding.DecodeString(o.Challenge)
	raw := device.Get(webauthn.RequestOptions{RPID: o.RPID, Challenge: ch}, "https://"+b.host)
	return url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {b.formRevisions[state]}, "challenge_id": {p.ChallengeID}, "credential": {string(raw)}}, state
}
func TestLoginIDPasskeyMarkup(t *testing.T) {
	for _, mode := range []string{"both", "autofill", "button", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, _ := passkeyEnv(t)
			ctx := context.Background()
			tn, _ := e.st.Tenants().GetByName(ctx, "acme")
			c, _ := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
			c.Extra["passkey_options"] = map[string]any{"challenge_ui": mode}
			if mode == "disabled" {
				c.Extra = nil
			}
			if err := e.st.Connections().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			page, _, _ := e.browser("acme.example.test").begin(t)
			body := page.Body.String()
			if mode == "disabled" {
				if strings.Contains(body, "za-webauthn") {
					t.Fatal("disabled markup")
				}
				return
			}
			p := readPasskeyPage(t, page)
			if p.ChallengeID == "" {
				t.Fatal("missing challenge")
			}
			autofill := strings.Contains(body, `autocomplete="username webauthn"`)
			button := strings.Contains(body, `id="za-passkey-button"`)
			if autofill != (mode != "button") || button != (mode != "autofill") {
				t.Fatalf("mode %s autofill=%v button=%v", mode, autofill, button)
			}
			for _, m := range regexp.MustCompile(`nonce="([^"]+)"`).FindAllStringSubmatch(body, -1) {
				if !strings.Contains(page.Header().Get("Content-Security-Policy"), "'nonce-"+m[1]+"'") {
					t.Fatal("nonce mismatch")
				}
			}
		})
	}
}
func TestHostedPasskeyLogin(t *testing.T) {
	e, u, d, _ := passkeyEnv(t)
	b := e.browser("acme.example.test")
	f, _ := passkeyForm(t, b, d)
	f.Set("username", "carol@acme.test")
	got := b.do(t, "POST", "/u/login/passkey", f)
	if got.Code != 302 {
		t.Fatalf("login: %d %s", got.Code, got.Body)
	}
	cookie := b.cookies[session.CookieName]
	if cookie == nil {
		t.Fatal("no cookie")
	}
	s, err := e.st.Sessions().GetByTokenHash(context.Background(), u.TenantID, secrets.HashToken(cookie.Value))
	if err != nil || s.UserID != u.UserID || len(s.AuthMethods) != 1 || s.AuthMethods[0].Name != "passkey" || !s.MFAAt.IsZero() {
		t.Fatalf("session: %+v %v", s, err)
	}
}
func TestHostedPasskeyDoubleSubmit(t *testing.T) {
	e, u, d, _ := passkeyEnv(t)
	b := e.browser("acme.example.test")
	f, state := passkeyForm(t, b, d)
	e.h.Store = &passkeyRaceStore{Store: e.st, state: state, gate: make(chan struct{})}
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		wg.Go(func() {
			r := httptest.NewRequest("POST", "https://acme.example.test/u/login/passkey", strings.NewReader(f.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range b.cookies {
				r.AddCookie(c)
			}
			w := httptest.NewRecorder()
			e.srv.ServeHTTP(w, r)
			results <- w
		})
	}
	wg.Wait()
	close(results)
	wins := 0
	for w := range results {
		if w.Code == 302 {
			wins++
		} else {
			p := readPasskeyPage(t, w)
			if p.ChallengeID == f.Get("challenge_id") || !strings.Contains(w.Body.String(), "passkey") {
				t.Fatal("no retry")
			}
		}
	}
	rows, err := e.st.Sessions().ListByUser(context.Background(), u.TenantID, u.UserID)
	if err != nil || wins != 1 || len(rows) != 1 {
		t.Fatalf("wins=%d rows=%d err=%v", wins, len(rows), err)
	}
}
func TestHostedPasskeyStaleCredential(t *testing.T) {
	for _, kind := range []string{"deleted", "disabled", "client-disabled", "rpid", "blocked"} {
		t.Run(kind, func(t *testing.T) {
			e, u, d, a := passkeyEnv(t)
			capture := &pwlEvents{}
			e.h.Recorder = capture
			b := e.browser("acme.example.test")
			f, _ := passkeyForm(t, b, d)
			ctx := context.Background()
			switch kind {
			case "deleted":
				if err := e.st.MFA().DeleteAuthenticator(ctx, u.TenantID, u.UserID, a.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled", "client-disabled":
				c, _ := e.st.Connections().GetByName(ctx, u.TenantID, "Username-Password-Authentication")
				if kind == "disabled" {
					c.Extra = nil
				} else {
					c.EnabledClients = nil
				}
				if err := e.st.Connections().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
			case "rpid":
				a.RPID = "other.example.test"
				if err := e.st.MFA().DeleteAuthenticator(ctx, u.TenantID, u.UserID, a.ID); err != nil {
					t.Fatal(err)
				}
				if err := e.st.WebAuthn().CreatePasskey(ctx, a, 20); err != nil {
					t.Fatal(err)
				}
			case "blocked":
				u.Blocked = true
				if err := e.st.Users().Update(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			w := b.do(t, "POST", "/u/login/passkey", f)
			if w.Code == 302 || b.cookies[session.CookieName] != nil {
				t.Fatal("stale credential logged in")
			}
			if kind != "blocked" {
				events := capture.of("gd_webauthn_challenge_failed")
				if len(events) != 1 || events[0].Details["first_factor"] != true {
					t.Fatalf("missing bounded failure log: %+v", capture.events)
				}
				code, ok := events[0].Details["failure_details"].(map[string]any)["errorCode"].(string)
				if !ok || (code != "key" && code != "rp_id" && code != "challenge") {
					t.Fatalf("unbounded reason %q", code)
				}
				if !strings.Contains(w.Body.String(), "We could not verify that passkey") {
					t.Fatalf("non-generic failure: %s", w.Body)
				}
			}
			if kind != "client-disabled" && kind != "disabled" {
				readPasskeyPage(t, w)
			}
			if kind == "blocked" {
				if !strings.Contains(w.Body.String(), "blocked") {
					t.Fatal("missing blocked message")
				}
			} else if !strings.Contains(w.Body.String(), "passkey") {
				t.Fatalf("not generic: %s", w.Body)
			}
		})
	}
}
func TestHostedPasskeyBinding(t *testing.T) {
	for _, kind := range []string{"transaction", "cookie", "origin", "csrf", "revision"} {
		t.Run(kind, func(t *testing.T) {
			e, _, d, _ := passkeyEnv(t)
			b := e.browser("acme.example.test")
			f, state := passkeyForm(t, b, d)
			switch kind {
			case "transaction":
				_, s, c := b.begin(t)
				f.Set("state", s)
				f.Set("csrf", c)
				f.Set("hosted_revision", b.formRevisions[s])
			case "cookie":
				b.cookies["za_txn_"+state] = &http.Cookie{Name: "za_txn_" + state, Value: "wrong"}
			case "origin":
				var cred map[string]any
				json.Unmarshal([]byte(f.Get("credential")), &cred)
				resp := cred["response"].(map[string]any)
				raw, _ := base64.RawURLEncoding.DecodeString(resp["clientDataJSON"].(string))
				var data map[string]any
				json.Unmarshal(raw, &data)
				data["origin"] = "https://evil.example.test"
				raw, _ = json.Marshal(data)
				resp["clientDataJSON"] = base64.RawURLEncoding.EncodeToString(raw)
				raw, _ = json.Marshal(cred)
				f.Set("credential", string(raw))
			case "csrf":
				f.Set("csrf", "wrong")
			case "revision":
				f.Set("hosted_revision", "-1")
			}
			w := b.do(t, "POST", "/u/login/passkey", f)
			if w.Code == 302 || b.cookies[session.CookieName] != nil {
				t.Fatal("binding bypass")
			}
		})
	}
}
func TestWebAuthnErrorNames(t *testing.T) {
	for _, name := range []string{"NotAllowedError", "<private-error>", "SecurityError"} {
		t.Run(name, func(t *testing.T) {
			e, _, d, _ := passkeyEnv(t)
			capture := &pwlEvents{}
			e.h.Recorder = capture
			b := e.browser("acme.example.test")
			f, _ := passkeyForm(t, b, d)
			f.Del("credential")
			f.Set("webauthn_error", name)
			w := b.do(t, "POST", "/u/login/passkey", f)
			events := capture.of("gd_webauthn_challenge_failed")
			if name == "NotAllowedError" {
				if len(events) != 0 {
					t.Fatal("cancellation logged")
				}
			} else {
				if len(events) != 1 {
					t.Fatalf("no failure log: %+v", capture.events)
				}
				expected := name
				if name == "<private-error>" {
					expected = "UnknownError"
				}
				detail := events[0].Details["failure_details"].(map[string]any)
				if detail["errorCode"] != expected {
					t.Fatalf("unbounded error: %+v", detail)
				}
			}
			p := readPasskeyPage(t, w)
			if p.ChallengeID == f.Get("challenge_id") || strings.Contains(w.Body.String(), name) {
				t.Fatal("error reflected or challenge reused")
			}
		})
	}
}

func tenantHandler(h http.HandlerFunc, st store.Store) http.Handler {
	return tenant.NewResolver(st.Tenants(), "", false).Middleware(h)
}

func TestHostedPasskeyAttackProtection(t *testing.T) {
	for _, kind := range []string{"brute-block", "reset", "failure-budget"} {
		t.Run(kind, func(t *testing.T) {
			e, u, d, _ := passkeyEnv(t)
			b := e.browser("acme.example.test")
			capture := &pwlEvents{}
			e.h.Recorder = capture
			ctx := context.Background()
			conn, _ := e.st.Connections().GetByName(ctx, u.TenantID, "Username-Password-Authentication")
			svc := e.h.protectionService()
			attempt := protection.Attempt{Tenant: mustTenant(t, e, "acme"), Connection: conn, Identifier: "alice@acme.test", IP: "192.0.2.1", Flow: "login"}
			n := 2
			if kind == "brute-block" {
				n = 3
			}
			if kind != "failure-budget" {
				for range n {
					dec, err := svc.Begin(ctx, attempt)
					if err != nil || !dec.Allowed {
						t.Fatalf("reserve %v %v", dec, err)
					}
					if err := svc.Finish(ctx, dec.Receipt, "failure"); err != nil {
						t.Fatal(err)
					}
				}
			}
			f, _ := passkeyForm(t, b, d)
			if kind == "failure-budget" {
				f.Set("credential", `{}`)
			}
			w := b.do(t, "POST", "/u/login/passkey", f)
			switch kind {
			case "brute-block":
				if w.Code != 429 || b.cookies[session.CookieName] != nil || len(capture.of("limit_wc")) != 1 {
					t.Fatalf("block=%d logs=%v", w.Code, capture.events)
				}
			case "reset":
				if w.Code != 302 {
					t.Fatalf("success=%d %s", w.Code, w.Body)
				}
				for range 3 {
					dec, err := svc.Begin(ctx, attempt)
					if err != nil || !dec.Allowed {
						t.Fatalf("success did not reset %v %v", dec, err)
					}
					if err := svc.Finish(ctx, dec.Receipt, "failure"); err != nil {
						t.Fatal(err)
					}
				}
			case "failure-budget":
				if w.Code != 401 || len(capture.of("gd_webauthn_challenge_failed")) != 1 {
					t.Fatalf("failed=%d logs=%v", w.Code, capture.events)
				}
				n, err := e.st.Protection().RiskCount(ctx, u.TenantID, "192.0.2.1", fixedNow())
				if err != nil || n != 1 {
					t.Fatalf("risk=%d %v", n, err)
				}
				// A failed unknown assertion consumes one of the 30 shared login-IP attempts.
				for range 29 {
					dec, err := svc.Begin(ctx, protection.Attempt{Tenant: attempt.Tenant, Connection: conn, IP: attempt.IP, Flow: "passkey-login-failure"})
					if err != nil || !dec.Allowed {
						t.Fatalf("budget early block %v %v", dec, err)
					}
					if err := svc.Finish(ctx, dec.Receipt, "failure"); err != nil {
						t.Fatal(err)
					}
				}
				dec, err := svc.Begin(ctx, protection.Attempt{Tenant: attempt.Tenant, Connection: conn, IP: attempt.IP, Flow: "passkey-login-failure"})
				if err != nil || dec.Allowed {
					t.Fatalf("failure did not spend IP budget %+v %v", dec, err)
				}
			}
		})
	}
}
func TestHostedPasskeyMFAConsentOrganization(t *testing.T) {
	t.Run("mfa", func(t *testing.T) {
		e, u, d, _ := passkeyEnv(t)
		ctx := context.Background()
		e.h.Authz.Wrapper, _ = keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
		g, _ := e.st.MFA().GetGuardian(ctx, u.TenantID)
		g.Factors = map[string]bool{"otp": true}
		g.Policies = []string{"all-applications"}
		if err := e.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
			t.Fatal(err)
		}
		if err := e.st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: u.TenantID, UserID: u.UserID, ID: "otp", Type: "otp", Confirmed: true}); err != nil {
			t.Fatal(err)
		}
		b := e.browser("acme.example.test")
		f, _ := passkeyForm(t, b, d)
		w := b.do(t, "POST", "/u/login/passkey", f)
		if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/u/mfa") {
			t.Fatalf("MFA bypass %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
		}
	})
	t.Run("consent", func(t *testing.T) {
		e, _, d, _ := passkeyEnv(t)
		ctx := context.Background()
		tn := mustTenant(t, e, "acme")
		c, _ := e.st.Clients().Get(ctx, tn.ID, "spa")
		c.IsFirstParty = false
		c.ThirdPartySecurityMode = "permissive"
		c.RedirectionPolicy = "allow_always"
		if err := e.st.Clients().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
		b := e.browser("acme.example.test")
		f, _ := passkeyForm(t, b, d)
		w := b.do(t, "POST", "/u/login/passkey", f)
		if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/u/consent") {
			t.Fatalf("consent bypass %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
		}
	})
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint("org-", auto), func(t *testing.T) {
			e, _, d, _ := passkeyEnv(t)
			org, _, u := organizationFixture(t, e, store.OrgBehaviorNoPrompt, auto, false)
			b := e.browser("acme.example.test")
			f, _ := passkeyForm(t, b, d, "organization", org.ID)
			w := b.do(t, "POST", "/u/login/passkey", f)
			loc, _ := url.Parse(w.Header().Get("Location"))
			member, err := e.st.Organizations().IsMember(context.Background(), org.TenantID, org.ID, u.UserID)
			if err != nil || member != auto || w.Code != 302 || auto && loc.Query().Get("code") == "" || !auto && loc.Query().Get("error") != "access_denied" {
				t.Fatalf("organization=%d %s member=%v %v", w.Code, loc, member, err)
			}
		})
	}
}
func TestHostedPasskeyFreshRetry(t *testing.T) {
	e, _, d, _ := passkeyEnv(t)
	b := e.browser("acme.example.test")
	f, originalState := passkeyForm(t, b, d)
	original, _ := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, originalState)
	f.Set("credential", `{}`)
	w := b.do(t, "POST", "/u/login/passkey", f)
	p := readPasskeyPage(t, w)
	if b.cookies["za_txn_"+originalState] != nil {
		t.Fatal("retry accumulated the old transaction cookie")
	}
	var o struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(p.Options, &o); err != nil {
		t.Fatal(err)
	}
	ch, _ := base64.RawURLEncoding.DecodeString(o.Challenge)
	f.Set("state", regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1])
	f.Set("csrf", csrfField.FindStringSubmatch(w.Body.String())[1])
	replacement, err := e.st.AuthTransactions().Get(context.Background(), original.TenantID, f.Get("state"))
	if err != nil || replacement.ID == original.ID || replacement.CookieHash == original.CookieHash || !replacement.ExpiresAt.Equal(original.ExpiresAt) || replacement.ClientID != original.ClientID || replacement.Params["redirect_uri"] != original.Params["redirect_uri"] {
		t.Fatalf("retry changed trusted authorization: %+v %v", replacement, err)
	}
	f.Set("challenge_id", p.ChallengeID)
	f.Set("hosted_revision", revisionFrom(t, w.Body.String()))
	f.Set("credential", string(d.Get(webauthn.RequestOptions{RPID: o.RPID, Challenge: ch}, "https://acme.example.test")))
	w = b.do(t, "POST", "/u/login/passkey", f)
	if w.Code != 302 {
		t.Fatalf("fresh challenge unusable %d %s", w.Code, w.Body)
	}
}
func TestHostedPasskeyEvents(t *testing.T) {
	e, _, d, _ := passkeyEnv(t)
	capture := &pwlEvents{}
	e.h.Recorder = capture
	original := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), capture)))
	})
	b := e.browser("acme.example.test")
	f, _ := passkeyForm(t, b, d)
	w := b.do(t, "POST", "/u/login/passkey", f)
	events := capture.of("s")
	if w.Code != 302 || len(events) != 1 {
		t.Fatalf("success events=%+v", capture.events)
	}
	raw, _ := json.Marshal(events[0].Details)
	if string(raw) != `{"prompts":[{"name":"login-id","performed_amr":["phr"]}]}` {
		t.Fatalf("success details=%s", raw)
	}
}

func TestHostedPasskeyHostBinding(t *testing.T) {
	for _, host := range []string{"other.acme.test", "globex.example.test"} {
		t.Run(host, func(t *testing.T) {
			e, u, d, _ := passkeyEnv(t)
			if host == "other.acme.test" {
				ctx := context.Background()
				cd := &store.CustomDomain{TenantID: u.TenantID, ID: "custom", Domain: host, Status: "ready"}
				if err := e.st.CustomDomains().Create(ctx, cd); err != nil {
					t.Fatal(err)
				}
				if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: host, TenantID: u.TenantID, DomainID: cd.ID, Kind: store.HostPublic, Active: true}); err != nil {
					t.Fatal(err)
				}
			}
			b := e.browser("acme.example.test")
			f, _ := passkeyForm(t, b, d)
			b.host = host
			w := b.do(t, "POST", "/u/login/passkey", f)
			if w.Code == 302 || !strings.Contains(w.Body.String(), "We could not verify that passkey") {
				t.Fatalf("host binding %d %s", w.Code, w.Body)
			}
			if b.cookies[session.CookieName] != nil {
				t.Fatal("cross-host session")
			}
		})
	}
}
func TestHostedPasskeyInvalidRPID(t *testing.T) {
	e, u, _, _ := passkeyEnv(t)
	ctx := context.Background()
	host := "bad.acme.test"
	cd := &store.CustomDomain{TenantID: u.TenantID, ID: "bad", Domain: host, RelyingPartyIdentifier: "unrelated.test", Status: "ready"}
	if err := e.st.CustomDomains().Create(ctx, cd); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: host, TenantID: u.TenantID, DomainID: cd.ID, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	b := e.browser(host)
	page, state, csrf := b.begin(t)
	if strings.Contains(page.Body.String(), "za-webauthn") {
		t.Fatal("invalid RP ID offered")
	}
	w := b.do(t, "POST", "/u/login/passkey", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {b.formRevisions[state]}, "challenge_id": {"invalid"}})
	if w.Code != 400 || strings.Contains(w.Body.String(), "za-webauthn") {
		t.Fatalf("invalid RP direct POST %d %s", w.Code, w.Body)
	}
}
func TestHostedPasskeyIDToken(t *testing.T) {
	e, u, d, _ := passkeyEnv(t)
	wrapper, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	km := keys.NewManager(e.st.SigningKeys(), wrapper)
	if err := km.Ensure(context.Background(), u.TenantID); err != nil {
		t.Fatal(err)
	}
	oh := &oauth.Handlers{Store: e.st, Minter: &oauth.Minter{Keys: km, Now: fixedNow}, Now: fixedNow}
	original := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tenantHandler(oh.OauthToken, e.st).ServeHTTP(w, r)
			return
		}
		original.ServeHTTP(w, r)
	})
	b := e.browser("acme.example.test")
	f, _ := passkeyForm(t, b, d)
	w := b.do(t, "POST", "/u/login/passkey", f)
	loc, _ := url.Parse(w.Header().Get("Location"))
	w = b.do(t, "POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "code": {loc.Query().Get("code")}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}})
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil || w.Code != 200 || tokens.IDToken == "" {
		t.Fatalf("exchange %d %s %v", w.Code, w.Body, err)
	}
	var claims map[string]any
	if err := km.Verify(context.Background(), u.TenantID, tokens.IDToken, &claims); err != nil {
		t.Fatal(err)
	}
	if _, ok := claims["amr"]; ok {
		t.Fatalf("passkey got MFA amr: %+v", claims)
	}
}

// Both requests read a validated transaction before either can consume it.
// This makes the network replay race independent of scheduler timing.
type passkeyRaceStore struct {
	store.Store
	state string
	gate  chan struct{}
	loads atomic.Int32
}

func (s *passkeyRaceStore) AuthTransactions() store.AuthTransactions {
	return passkeyRaceTransactions{s.Store.AuthTransactions(), s}
}

type passkeyRaceTransactions struct {
	store.AuthTransactions
	owner *passkeyRaceStore
}

func (s passkeyRaceTransactions) Get(ctx context.Context, tid, id string) (*store.AuthTransaction, error) {
	t, err := s.AuthTransactions.Get(ctx, tid, id)
	if id == s.owner.state && err == nil {
		n := s.owner.loads.Add(1)
		if n == 2 {
			close(s.owner.gate)
		}
		if n <= 2 {
			select {
			case <-s.owner.gate:
			case <-time.After(10 * time.Second):
				return nil, fmt.Errorf("concurrent submit did not enter")
			}
		}
	}
	return t, err
}
func TestHostedPasskeyActions(t *testing.T) {
	e, u, d, _ := passkeyEnv(t)
	wrapper, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, wrapper)
	a.Bind(t, u.TenantID, actions.TriggerPostLogin, a.Deploy(t, u.TenantID, actions.TriggerPostLogin, "deny-passkey", `exports.onExecutePostLogin=(event,api)=>{ if (JSON.stringify(event).includes('clientDataJSON') || Object.keys(event.request.body).length) throw Error('credential leaked'); api.access.deny('policy refused'); };`))
	e.h.Authz.Actions = a.Engine
	e.h.Authz.Wrapper = wrapper
	b := e.browser("acme.example.test")
	f, _ := passkeyForm(t, b, d)
	w := b.do(t, "POST", "/u/login/passkey", f)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Query().Get("error") != "access_denied" || !strings.Contains(loc.Query().Get("error_description"), "policy refused") {
		t.Fatalf("post-login Action bypass %d %s %s", w.Code, loc, w.Body)
	}
}

func assertSessionMethods(t *testing.T, b *browser, want ...string) {
	t.Helper()
	tn := mustTenant(t, b.e, "acme")
	cookie := b.cookies[session.CookieName]
	if cookie == nil {
		t.Fatal("no authenticated session")
	}
	s, err := b.e.st.Sessions().GetByTokenHash(context.Background(), tn.ID, secrets.HashToken(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range s.AuthMethods {
		name := m.Name
		if m.Type != "" {
			name += ":" + m.Type
		}
		got = append(got, name)
		if m.At.IsZero() {
			t.Fatal("method has no time")
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("session methods=%v want=%v", got, want)
	}
}

func TestLoginIDPasskeyPrerequisites(t *testing.T) {
	for _, kind := range []string{"classic", "combined", "username", "custom-no-import", "password-disabled"} {
		t.Run(kind, func(t *testing.T) {
			e, u, _, _ := passkeyEnv(t)
			ctx := context.Background()
			conn, _ := e.st.Connections().GetByName(ctx, u.TenantID, "Username-Password-Authentication")
			cfg, _ := e.st.HostedLogins().Get(ctx, u.TenantID)
			switch kind {
			case "classic":
				cfg.Prompts["universal_login_experience"] = "classic"
			case "combined":
				cfg.Prompts["identifier_first"] = false
			case "username":
				conn.RequiresUsername = true
			case "custom-no-import":
				conn.EnabledDatabaseCustomization = true
				conn.ImportMode = false
			case "password-disabled":
				conn.Extra["authentication_methods"].(map[string]any)["password"] = map[string]any{"enabled": false}
			}
			if err := e.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
			if err := e.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
				t.Fatal(err)
			}
			page, _, _ := e.browser("acme.example.test").begin(t)
			if strings.Contains(page.Body.String(), "za-webauthn") || strings.Contains(page.Body.String(), `autocomplete="username webauthn"`) {
				t.Fatalf("unmet prerequisite offered: %s", kind)
			}
		})
	}
}
