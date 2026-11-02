package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func gatePolicy(t *testing.T, e *env, factors map[string]bool) {
	t.Helper()
	g, err := e.st.MFA().GetGuardian(context.Background(), e.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	g.Policies = []string{"all-applications"}
	g.Factors = factors
	if err = e.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	e.h.Wrapper, _ = keys.NewLocalWrapper(make([]byte, 32))
}
func TestGateSSOSecondAppChallenges(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-time.Minute))
	if location(t, e.get(t, goodQuery(), ck)).Query().Get("code") == "" {
		t.Fatal("first app did not authorize")
	}
	gatePolicy(t, e, map[string]bool{"otp": true})
	rec := e.get(t, with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb"), ck)
	e.txnAt(t, rec, "/u/mfa")
}
func TestGatePromptNoneInteractionRequired(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"otp": true})
	loc := location(t, e.get(t, with(goodQuery(), "prompt", "none"), ck))
	if loc.Query().Get("error") != "interaction_required" || loc.Query().Get("code") != "" {
		t.Fatalf("location=%s", loc)
	}
}
func TestGateNoFactorAccessDenied(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"webauthn-roaming": true})
	loc := location(t, e.get(t, goodQuery(), ck))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("error_description") != "MFA is required but no factor is enabled" {
		t.Fatalf("location=%s", loc)
	}
}
func TestGateSkipsAfterSessionMFA(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"otp": true})
	s, err := e.st.Sessions().GetByTokenHash(context.Background(), e.tenant.ID, secrets.HashToken(ck.Value))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.st.Sessions().MarkMFA(context.Background(), e.tenant.ID, s.ID, fixedNow()); err != nil {
		t.Fatal(err)
	}
	loc := location(t, e.get(t, goodQuery(), ck))
	if loc.Query().Get("code") == "" {
		t.Fatalf("location=%s", loc)
	}
}
func TestGateDeviceFlow(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"email": true})
	dc := e.deviceCode(t)
	e.txnAt(t, e.continueDevice(t, dc, ck), "/u/mfa")
	if e.storedCode(t, dc).Status != store.DeviceCodePending {
		t.Fatal("approved device before MFA")
	}
}

type noMFAStore struct{ store.Store }

func (noMFAStore) MFA() store.MFA { return store.UnimplementedMFA{} }
func TestGateUnavailableStoreIsPolicyNone(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	e.h.Store = noMFAStore{e.h.Store}
	loc := location(t, e.get(t, goodQuery(), ck))
	if loc.Query().Get("code") == "" {
		t.Fatalf("location=%s", loc)
	}
}

func TestGateBrowserBindings(t *testing.T) {
	for _, kind := range []string{"remember", "device"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ck := e.login(t, fixedNow())
			gatePolicy(t, e, map[string]bool{"otp": true})
			r := httptest.NewRequest("GET", "https://acme.example.test/u/mfa", nil)
			r.AddCookie(ck)
			s, _ := e.st.Sessions().GetByTokenHash(r.Context(), e.tenant.ID, secrets.HashToken(ck.Value))
			u, _ := e.st.Users().Get(r.Context(), e.tenant.ID, s.UserID)
			rec := httptest.NewRecorder()
			if err := e.h.Sessions.SetMFABrowser(r.Context(), rec, u, kind); err != nil {
				t.Fatal(err)
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies=%v", cookies)
			}
			c := cookies[0]
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" {
				t.Fatalf("cookie=%+v", c)
			}
			browser, err := e.st.MFA().GetBrowser(r.Context(), e.tenant.ID, secrets.HashToken(c.Value), fixedNow())
			if err != nil || browser.Hash == c.Value || browser.UserID != u.UserID || browser.Kind != kind {
				t.Fatalf("stored=%+v %v", browser, err)
			}
			r.AddCookie(c)
			valid, err := e.h.Sessions.MFABrowserValid(r.Context(), r, u, kind)
			if err != nil || !valid {
				t.Fatalf("valid=%v %v", valid, err)
			}
			other := *u
			other.UserID = "other"
			if valid, _ = e.h.Sessions.MFABrowserValid(r.Context(), r, &other, kind); valid {
				t.Fatal("cross-user cookie accepted")
			}
			other = *u
			other.TenantID = "other"
			if valid, _ = e.h.Sessions.MFABrowserValid(r.Context(), r, &other, kind); valid {
				t.Fatal("cross-tenant cookie accepted")
			}
			if err = e.st.MFA().BumpRememberEpoch(r.Context(), e.tenant.ID, u.UserID); err != nil {
				t.Fatal(err)
			}
			u, _ = e.st.Users().Get(r.Context(), e.tenant.ID, u.UserID)
			if valid, _ = e.h.Sessions.MFABrowserValid(r.Context(), r, u, kind); valid {
				t.Fatal("old epoch accepted")
			}
			fresh := httptest.NewRecorder()
			if err = e.h.Sessions.SetMFABrowser(r.Context(), fresh, u, kind); err != nil {
				t.Fatal(err)
			}
			r.Header.Del("Cookie")
			r.AddCookie(fresh.Result().Cookies()[0])
			if valid, _ = e.h.Sessions.MFABrowserValid(r.Context(), r, u, kind); !valid {
				t.Fatal("fresh current-epoch cookie rejected")
			}
			e.h.Sessions.Now = func() time.Time { return fixedNow().Add(30 * 24 * time.Hour) }
			if valid, _ = e.h.Sessions.MFABrowserValid(r.Context(), r, u, kind); valid {
				t.Fatal("expired cookie accepted")
			}
		})
	}
}

func gateSession(t *testing.T, e *env, c *http.Cookie) *store.LoginSession {
	t.Helper()
	s, err := e.st.Sessions().GetByTokenHash(context.Background(), e.tenant.ID, secrets.HashToken(c.Value))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func gateRequest(e *env, ck *http.Cookie, rec *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest("POST", "https://acme.example.test/u/mfa", nil)
	r = r.WithContext(tenant.WithResolved(r.Context(), e.res()))
	r.AddCookie(ck)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 {
			r.AddCookie(c)
		}
	}
	return r
}
func TestGateMFACompleteFreshAndSingleUse(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"otp": true})
	rec := e.get(t, goodQuery(), ck)
	txn := e.txnAt(t, rec, "/u/mfa")
	r := gateRequest(e, ck, rec)
	s := gateSession(t, e, ck)
	pending, err := e.h.PendingMFA(r.Context(), r, e.res(), txn, s)
	if err != nil || !pending.Requirement.Enroll {
		t.Fatalf("pending=%+v %v", pending, err)
	}
	failed := httptest.NewRecorder()
	e.h.MFAComplete(failed, r, e.res(), txn, s)
	if failed.Code != 400 {
		t.Fatalf("unproved completion: %d %s", failed.Code, failed.Header().Get("Location"))
	}
	e.h.Sessions.Now = func() time.Time { return fixedNow().Add(time.Second) }
	if err = e.h.Sessions.MarkMFA(r.Context(), s); err != nil {
		t.Fatal(err)
	}
	completed := httptest.NewRecorder()
	e.h.MFAComplete(completed, r, e.res(), txn, s)
	if location(t, completed).Query().Get("code") == "" {
		t.Fatal("MFA did not resume authorization")
	}
	replay := httptest.NewRecorder()
	e.h.MFAComplete(replay, r, e.res(), txn, s)
	if replay.Code != 400 {
		t.Fatalf("replay=%d", replay.Code)
	}
}
func TestGatePendingMFARejectsBindings(t *testing.T) {
	for _, bad := range []string{"cookie", "session", "tenant", "origin", "epoch", "expired", "seal"} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			ck := e.login(t, fixedNow())
			gatePolicy(t, e, map[string]bool{"otp": true})
			rec := e.get(t, goodQuery(), ck)
			txn := e.txnAt(t, rec, "/u/mfa")
			r := gateRequest(e, ck, rec)
			s := gateSession(t, e, ck)
			res := e.res()
			switch bad {
			case "cookie":
				r.Header.Del("Cookie")
				r.AddCookie(ck)
			case "session":
				s.ID = "other"
			case "tenant":
				other := *res.Tenant
				other.ID = "other"
				res.Tenant = &other
			case "origin":
				res.Host = "other.example.test"
			case "epoch":
				if err := e.st.MFA().BumpRememberEpoch(r.Context(), res.Tenant.ID, s.UserID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				e.h.Now = func() time.Time { return fixedNow().Add(TxnLifetime) }
			case "seal":
				if err := e.st.AuthTransactions().Delete(r.Context(), res.Tenant.ID, txn.ID); err != nil {
					t.Fatal(err)
				}
				txn.Params[mfaPendingKey] = "broken"
				if err := e.st.AuthTransactions().Create(r.Context(), txn); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.h.PendingMFA(r.Context(), r, res, txn, s); err == nil {
				t.Fatal("accepted invalid pending state")
			}
		})
	}
}
func TestGateActionForceSurvivesConsentAndCompletes(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-time.Hour))
	gatePolicy(t, e, map[string]bool{"otp": true})
	s := gateSession(t, e, ck)
	if err := e.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: e.tenant.ID, UserID: s.UserID, ID: "totp|dev_test", Type: "totp", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Sessions().MarkMFA(context.Background(), e.tenant.ID, s.ID, fixedNow().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	s = gateSession(t, e, ck)
	e.tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	eff := &actions.Effects{MFA: &actions.MFAEffects{Mode: "challenge", Factors: [][]string{{"otp"}}}, IDClaims: map[string]any{"kept": "yes"}}
	sealed, err := e.h.sealConsent(e.tenant.ID, "consent", s.ID, "spa", eff)
	if err != nil {
		t.Fatal(err)
	}
	eff, err = e.h.consentEffects(e.tenant.ID, &store.AuthTransaction{ID: "consent", ClientID: "spa", Params: map[string]string{effectsKey: sealed, sessionKey: s.ID}})
	if err != nil || eff.MFA == nil {
		t.Fatalf("lost consent MFA: %+v %v", eff, err)
	}
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize", nil)
	r = r.WithContext(tenant.WithResolved(r.Context(), e.res()))
	r.AddCookie(ck)
	client, _ := e.st.Clients().Get(r.Context(), e.tenant.ID, "spa")
	rec := httptest.NewRecorder()
	e.h.approve(rec, r, e.res(), client, flowReq{Request: ParseRequest(goodQuery())}, s, []string{"openid"}, eff)
	txn := e.txnAt(t, rec, "/u/mfa")
	r = gateRequest(e, ck, rec)
	e.h.Sessions.Now = func() time.Time { return fixedNow().Add(time.Second) }
	if err = e.h.Sessions.MarkMFA(r.Context(), s); err != nil {
		t.Fatal(err)
	}
	completed := httptest.NewRecorder()
	e.h.MFAComplete(completed, r, e.res(), txn, s)
	loc := location(t, completed)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("loop after forced proof: %s", loc)
	}
	ac, err := e.st.AuthCodes().Consume(r.Context(), e.tenant.ID, secrets.HashToken(code), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := actions.OpenEffects(e.h.Wrapper, e.tenant.ID, actions.SealCode, ac.ActionEffects, ac.CodeHash)
	if err != nil || actual.IDClaims["kept"] != "yes" {
		t.Fatalf("effects=%+v %v", actual, err)
	}
}
func TestGateUnavailableStoreActionFailsClosed(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	s := gateSession(t, e, ck)
	e.h.Store = noMFAStore{e.h.Store}
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize", nil)
	client, _ := e.st.Clients().Get(r.Context(), e.tenant.ID, "spa")
	rec := httptest.NewRecorder()
	e.h.approve(rec, r, e.res(), client, flowReq{Request: ParseRequest(goodQuery())}, s, []string{"openid"}, &actions.Effects{MFA: &actions.MFAEffects{Provider: "any"}})
	if location(t, rec).Query().Get("error") != "access_denied" {
		t.Fatalf("location=%s", rec.Header().Get("Location"))
	}
}
func TestGateCompletedLoginRecordsKnownDevice(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	rec := e.get(t, goodQuery(), ck)
	if location(t, rec).Query().Get("code") == "" {
		t.Fatal("login failed")
	}
	var dev *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_mfa_dev" {
			dev = c
		}
	}
	if dev == nil {
		t.Fatal("completed login did not record known device")
	}
}

func TestGateCompletedActionKeepsFactorRestrictions(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	gatePolicy(t, e, map[string]bool{"email": true})
	s := gateSession(t, e, ck)
	s.MFAAt = fixedNow()
	e.tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize", nil)
	r = r.WithContext(context.WithValue(r.Context(), mfaCompletedKey{}, s.ID))
	client, _ := e.st.Clients().Get(r.Context(), e.tenant.ID, "spa")
	rec := httptest.NewRecorder()
	e.h.approve(rec, r, e.res(), client, flowReq{Request: ParseRequest(goodQuery())}, s, []string{"openid"}, &actions.Effects{MFA: &actions.MFAEffects{Mode: "challenge", Factors: [][]string{{"otp"}}}})
	if location(t, rec).Query().Get("error") != "access_denied" {
		t.Fatalf("disabled Action factor was bypassed: %s", rec.Header().Get("Location"))
	}
}
func TestGateRememberAndConfidenceCookies(t *testing.T) {
	for _, kind := range []string{"remember", "device"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ck := e.login(t, fixedNow())
			gatePolicy(t, e, map[string]bool{"otp": true})
			s := gateSession(t, e, ck)
			u, _ := e.st.Users().Get(context.Background(), e.tenant.ID, s.UserID)
			if err := e.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: e.tenant.ID, UserID: s.UserID, ID: "totp|dev_test", Type: "totp", Confirmed: true}); err != nil {
				t.Fatal(err)
			}
			if kind == "device" {
				g, _ := e.st.MFA().GetGuardian(context.Background(), e.tenant.ID)
				g.Policies = []string{"confidence-score"}
				if err := e.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
					t.Fatal(err)
				}
			}
			rec := httptest.NewRecorder()
			if err := e.h.Sessions.SetMFABrowser(context.Background(), rec, u, kind); err != nil {
				t.Fatal(err)
			}
			c := rec.Result().Cookies()[0]
			if location(t, e.get(t, goodQuery(), ck, c)).Query().Get("code") == "" {
				t.Fatal("valid browser did not satisfy MFA")
			}
			e.txnAt(t, e.get(t, goodQuery(), ck), "/u/mfa")
			if err := e.st.MFA().BumpRememberEpoch(context.Background(), e.tenant.ID, s.UserID); err != nil {
				t.Fatal(err)
			}
			e.txnAt(t, e.get(t, goodQuery(), ck, c), "/u/mfa")
		})
	}
}

func TestGateRedirectContinuationChallenges(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.PostLogin(t, e.tenant.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.test/');exports.onContinuePostLogin=(e,a)=>a.idToken.setCustomClaim('continued',true)`)
	ck := e.login(t, fixedNow())
	loc := location(t, e.get(t, goodQuery(), ck))
	if loc.Host != "step.test" {
		t.Fatalf("redirect=%s", loc)
	}
	gatePolicy(t, e.env, map[string]bool{"otp": true})
	e.h.Wrapper = e.w
	r := httptest.NewRequest("GET", "https://acme.example.test/continue?state="+url.QueryEscape(loc.Query().Get("state")), nil)
	r.AddCookie(ck)
	r = r.WithContext(tenant.WithResolved(r.Context(), e.res()))
	rec := httptest.NewRecorder()
	e.h.Continue(rec, r)
	e.txnAt(t, rec, "/u/mfa")
	if e.codes != 0 {
		t.Fatal("continuation issued a code before MFA")
	}
}
