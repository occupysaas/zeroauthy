package login

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A proved first factor is only transaction authority. Abandoning MFA must
// leave invitation ownership, membership, login statistics and SSO untouched.
func TestNoSideEffectsBeforeMFA(t *testing.T) {
	for _, invited := range []bool{false, true} {
		name := "auto-membership"
		if invited {
			name = "invitation"
		}
		t.Run("password/"+name, func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp")
			secret := f.enrolled(t, "otp", true)
			org, conn, u := organizationFixture(t, f.env, store.OrgBehaviorNoPrompt, true, false)
			args := []string{"organization", org.ID}
			if invited {
				in := &store.OrganizationInvitation{TenantID: org.TenantID, OrganizationID: org.ID, ID: "invite", ClientID: "spa", InviteeEmail: u.Email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
				if err := f.st.OrganizationsII().CreateInvitation(context.Background(), in); err != nil {
					t.Fatal(err)
				}
				args = append(args, "invitation", "bearer")
			}
			_, state, csrf := f.b.begin(t, args...)
			rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if loc.Path != "/u/mfa" {
				t.Fatalf("MFA gate: %d %s %s", rec.Code, loc, rec.Body)
			}
			assertNoLoginEffects(t, f.env, u, org, invited)
			silent := orgAuthorize(f.b, org.ID, "none")
			sl, _ := url.Parse(silent.Header().Get("Location"))
			if sl.Query().Get("code") != "" {
				t.Fatal("pending login used as SSO", sl)
			}
			f.state = loc.Query().Get("state")
			f.page(t, "/u/mfa")
			rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
			loc, _ = url.Parse(rec.Header().Get("Location"))
			if loc.Query().Get("code") == "" {
				t.Fatalf("completion: %d %s %s", rec.Code, loc, rec.Body)
			}
			got, err := f.st.Users().Get(context.Background(), u.TenantID, u.UserID)
			if err != nil || got.LoginsCount != u.LoginsCount+1 {
				t.Fatalf("counter after completion: %+v %v", got, err)
			}
			member, err := f.st.Organizations().IsMember(context.Background(), u.TenantID, org.ID, u.UserID)
			if err != nil || !member {
				t.Fatal("membership after completion", member, err)
			}
			if f.b.cookies[session.CookieName] == nil {
				t.Fatal("no completed session")
			}
		})
	}
	for _, factor := range []string{"passwordless", "social", "passkey"} {
		for _, invited := range []bool{false, true} {
			name := "auto-membership"
			if invited {
				name = "invitation"
			}
			t.Run(factor+"/"+name, func(t *testing.T) { testOtherFactorBeforeMFA(t, factor, invited) })
		}
	}
}
func assertNoLoginEffects(t *testing.T, e *env, u *store.User, org *store.Organization, invited bool) {
	t.Helper()
	ctx := context.Background()
	got, err := e.st.Users().Get(ctx, u.TenantID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LoginsCount != u.LoginsCount || !reflect.DeepEqual(got.LastLogin, u.LastLogin) {
		t.Errorf("login statistics changed before completion: count %d -> %d", u.LoginsCount, got.LoginsCount)
	}
	rows, err := e.st.Sessions().ListByUser(ctx, u.TenantID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d durable sessions before completion", len(rows))
	}
	if org != nil {
		member, err := e.st.Organizations().IsMember(ctx, u.TenantID, org.ID, u.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if member {
			t.Error("membership added before completion")
		}
	}
	if invited {
		if _, err := e.st.OrganizationsII().GetInvitation(ctx, u.TenantID, org.ID, "invite"); err != nil {
			t.Error("invitation consumed before completion", err)
		}
	}
}

func TestConsentAfterMFA(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	_, state, csrf := f.b.begin(t, "client_id", "partner", "redirect_uri", "https://partner.example/cb", "audience", "https://api.acme.test", "scope", "read:things")
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("consent preceded MFA: %s", loc)
	}
	assertNoLoginEffects(t, f.env, u, nil, false)
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/consent" {
		t.Fatalf("consent missing after MFA: %s %s", loc, rec.Body)
	}
	assertNoLoginEffects(t, f.env, u, nil, false)
	state = loc.Query().Get("state")
	page := f.b.do(t, "GET", loc.RequestURI(), nil)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || m == nil {
		t.Fatalf("consent page %d %s", page.Code, page.Body)
	}
	rec = f.b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {m[1]}, "action": {"accept"}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("consent finish: %s %s", loc, rec.Body)
	}
	got, _ := f.st.Users().Get(context.Background(), u.TenantID, u.UserID)
	if got.LoginsCount != u.LoginsCount+1 {
		t.Fatal("login not committed once", got.LoginsCount)
	}
}

type loginCommitFailure struct{ store.Store }
type loginCountFailure struct{ store.Users }

func (s loginCommitFailure) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(loginCommitFailure{tx}) })
}
func (s loginCommitFailure) Users() store.Users { return loginCountFailure{s.Store.Users()} }
func (s loginCountFailure) RecordLogin(context.Context, string, string, time.Time, string) error {
	return errors.New("injected login commit failure")
}
func TestSideEffectsOneTransaction(t *testing.T) {
	e := newEnv(t)
	org, conn, u := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, false)
	u.EmailVerified = true
	ctx := context.Background()
	if err := e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: u.TenantID, OrganizationID: org.ID, ID: "invite", ClientID: "spa", InviteeEmail: u.Email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	failing := loginCommitFailure{e.st}
	e.h.Store = failing
	e.h.Authz.Store = failing
	e.h.Sessions.Store = failing
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "organization", org.ID, "invitation", "bearer")
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") != "" {
		t.Error("issued code after failed commit", loc)
	}
	assertNoLoginEffects(t, e, u, org, true)
	if _, err := e.st.OrganizationsII().GetInvitationReceipt(ctx, u.TenantID, state); !errors.Is(err, store.ErrNotFound) {
		t.Error("receipt survived failed commit", err)
	}
	if c := b.cookies[session.CookieName]; c != nil && c.Value != "" {
		t.Error("SSO cookie escaped failed commit")
	}
}

func testOtherFactorBeforeMFA(t *testing.T, factor string, invited bool) {
	ctx := context.Background()
	var e *env
	var u *store.User
	var device *webauthntest.Authenticator
	var social *socialEnv
	var pwl *pwlFixture
	switch factor {
	case "passkey":
		e, u, device, _ = passkeyEnv(t)
	case "social":
		social = newSocialEnv(t)
		e = social.env
		toApp(t, social.explicitLogin(t, e.browser("acme.example.test"), social.idp, "corp", "Invited"), "app.acme.test")
		u, _ = e.st.Users().Get(ctx, social.tenant.ID, social.identityID("Invited"))
	case "passwordless":
		e = newEnv(t)
		pwl = enablePasswordless(t, e)
		appCode(t, pwl.loginEmail(t, e.browser("acme.example.test"), "invited@example.test"))
		u = pwl.userByEmail(t, "invited@example.test")
	}
	if u == nil {
		t.Fatal("missing fixture user")
	}
	rows, err := e.st.Sessions().ListByUser(ctx, u.TenantID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err = e.st.Sessions().Delete(ctx, u.TenantID, row.ID); err != nil {
			t.Fatal(err)
		}
	}
	f := newMFAFixtureForEnv(t, e)
	f.uid = u.UserID
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, false)
	connName := "Username-Password-Authentication"
	if factor == "social" {
		connName = "corp"
	}
	if factor == "passwordless" {
		connName = "email"
	}
	conn, err := e.st.Connections().GetByName(ctx, u.TenantID, connName)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: u.TenantID, OrganizationID: org.ID, ConnectionID: conn.ID, AssignMembershipOnLogin: true, ShowAsButton: true}, factor != "passkey"); err != nil {
		t.Fatal(err)
	}
	u, err = e.st.Users().Get(ctx, u.TenantID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"organization", org.ID}
	if invited {
		u.EmailVerified = true
		if err = e.st.Users().Update(ctx, u); err != nil {
			t.Fatal(err)
		}
		in := &store.OrganizationInvitation{TenantID: u.TenantID, OrganizationID: org.ID, ID: "invite", ClientID: "spa", InviteeEmail: u.Email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
		if err = e.st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
			t.Fatal(err)
		}
		args = append(args, "invitation", "bearer")
	}
	var rec *httptest.ResponseRecorder
	switch factor {
	case "passkey":
		form, _ := passkeyForm(t, f.b, device, args...)
		rec = f.b.do(t, "POST", "/u/login/passkey", form)
	case "passwordless":
		rec = pwl.loginEmail(t, f.b, u.Email, args...)
	case "social":
		args = append(args, "connection", "corp")
		page := social.authorizeTo(t, f.b, "spa", args...)
		rec = f.b.do(t, "GET", page, nil)
		callback := social.idp.authorize(t, providerURL(t, rec), "Invited")
		rec = f.b.do(t, "GET", callback, nil)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("MFA gate: %d %s %s", rec.Code, loc, rec.Body)
	}
	assertNoLoginEffects(t, e, u, org, invited)
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("completion: %d %s %s", rec.Code, loc, rec.Body)
	}
	got, err := e.st.Users().Get(ctx, u.TenantID, u.UserID)
	if err != nil || got.LoginsCount != u.LoginsCount+1 {
		t.Fatal("counter after completion", got, err)
	}
	member, err := e.st.Organizations().IsMember(ctx, u.TenantID, org.ID, u.UserID)
	if err != nil || !member {
		t.Fatal("membership after completion", member, err)
	}
}

func TestPendingLoginCannotBecomeSSO(t *testing.T) {
	for _, mode := range []string{"cookie", "origin", "expiry", "blocked", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp")
			f.enrolled(t, "otp", true)
			f.begin(t)
			u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
			switch mode {
			case "cookie":
				delete(f.b.cookies, "za_pending_login")
			case "origin":
				tn := mustTenant(t, f.env, "acme")
				tn.Domains = append(tn.Domains, "login.acme.test")
				if err := f.st.Tenants().Update(context.Background(), tn); err != nil {
					t.Fatal(err)
				}
				f.b.host = "login.acme.test"
			case "expiry":
				*f.clock = f.clock.Add(30 * time.Minute)
			case "blocked":
				u.Blocked = true
				if err := f.st.Users().Update(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if _, err := f.st.Users().BumpVersion(context.Background(), u.TenantID, u.UserID); err != nil {
					t.Fatal(err)
				}
			}
			rec := f.b.do(t, "GET", "/u/mfa?state="+f.state, nil)
			if rec.Code == 200 || rec.Code == 303 {
				t.Errorf("invalid pending identity usable: %s %d %s", mode, rec.Code, rec.Header().Get("Location"))
			}
			rows, err := f.st.Sessions().ListByUser(context.Background(), u.TenantID, u.UserID)
			if err != nil || len(rows) != 0 {
				t.Fatal("invalid pending identity created SSO", rows, err)
			}
		})
	}
}

func TestHostedActionsProspectiveStatsBeforeMFA(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	a.PostLogin(t, f.tn.ID, "prospective", `exports.onExecutePostLogin=(e,a)=>{if(e.stats.logins_count!==1)throw Error('stale stats');a.redirect.sendUserTo('https://step.example/');};exports.onContinuePostLogin=(e,a)=>{if(e.stats.logins_count!==1)throw Error('changed stats');a.user.setAppMetadata('action_runs',1);};`)
	f.h.Authz.Actions = a.Engine
	old := f.srv
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/continue" {
			tenantHandler(f.h.Authz.Continue, f.st).ServeHTTP(w, r)
			return
		}
		old.ServeHTTP(w, r)
	})
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	_, state, csrf := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "step.example" {
		t.Fatalf("Action did not run before MFA: %s %s", loc, rec.Body)
	}
	assertNoLoginEffects(t, f.env, u, nil, false)
	rec = f.b.do(t, "GET", "/continue?state="+loc.Query().Get("state"), nil)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("continuation MFA: %s %s", loc, rec.Body)
	}
	assertNoLoginEffects(t, f.env, u, nil, false)
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	appCode(t, rec)
	saved, err := f.st.Users().Get(context.Background(), u.TenantID, u.UserID)
	if err != nil || saved.LoginsCount != 1 || saved.AppMetadata["action_runs"] != float64(1) {
		t.Fatal("Action or count changed on completion", saved, err)
	}
}

func TestPendingMFAKeepsExistingSSO(t *testing.T) {
	f := newMFAFixture(t)
	// Complete one login first; a later abandoned reauthentication must neither
	// replace nor delete its valid SSO authority.
	_, state, csrf := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	appCode(t, rec)
	original := f.b.cookies[session.CookieName].Value
	f.policy(t, "otp")
	f.enrolled(t, "otp", true)
	_, state, csrf = f.b.begin(t, "prompt", "login")
	rec = f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("MFA missing: %s", loc)
	}
	if got := f.b.cookies[session.CookieName]; got == nil || got.Value != original {
		t.Fatal("abandoned login replaced SSO")
	}
	rows, err := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
	if err != nil || len(rows) != 1 {
		t.Fatal("abandoned login changed sessions", rows, err)
	}
	u, err := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	if err != nil || u.LoginsCount != 1 {
		t.Fatal("abandoned reauthentication counted", u, err)
	}
}

type codeCommitFailure struct{ store.Store }
type completionCodeFailure struct{ store.AuthCodes }

func (s codeCommitFailure) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(codeCommitFailure{tx}) })
}
func (s codeCommitFailure) AuthCodes() store.AuthCodes {
	return completionCodeFailure{s.Store.AuthCodes()}
}
func (s completionCodeFailure) Create(context.Context, *store.AuthCode) error {
	return errors.New("injected code commit failure")
}

func TestSideEffectsOneTransactionAfterConsent(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	ctx := context.Background()
	org, conn, u := organizationFixture(t, f.env, store.OrgBehaviorNoPrompt, true, false)
	client, err := f.st.Clients().Get(ctx, u.TenantID, "partner")
	if err != nil {
		t.Fatal(err)
	}
	client.OrganizationUsage = store.OrgUsageAllow
	if err = f.st.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: u.TenantID, OrganizationID: org.ID, ID: "invite", ClientID: "partner", InviteeEmail: u.Email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err = f.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	_, state, csrf := f.b.begin(t, "organization", org.ID, "invitation", "bearer", "client_id", "partner", "redirect_uri", "https://partner.example/cb", "audience", "https://api.acme.test", "scope", "read:things")
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatal("MFA missing", loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/consent" {
		t.Fatal("consent missing", loc, rec.Body)
	}
	page := f.b.do(t, "GET", loc.RequestURI(), nil)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("consent unavailable", page.Code, page.Body)
	}
	failing := codeCommitFailure{f.st}
	f.h.Authz.Store = failing
	rec = f.b.do(t, "POST", "/u/consent", url.Values{"state": {loc.Query().Get("state")}, "csrf": {m[1]}, "action": {"accept"}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") != "" {
		t.Fatal("code despite rollback", loc)
	}
	assertNoLoginEffects(t, f.env, u, org, true)
	if _, err = f.st.UserGrants().Find(ctx, u.TenantID, "partner", u.UserID, "https://api.acme.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("consent persisted after code failure", err)
	}
	if _, err = f.st.OrganizationsII().GetInvitationReceipt(ctx, u.TenantID, state); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("invitation receipt persisted", err)
	}
	if f.b.cookies[session.CookieName] != nil {
		t.Fatal("session cookie despite rollback")
	}
}

type rotationCommitFailure struct{ store.Store }
type rotationSessionFailure struct{ store.Sessions }

func (s rotationCommitFailure) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(rotationCommitFailure{tx}) })
}
func (s rotationCommitFailure) Sessions() store.Sessions {
	return rotationSessionFailure{s.Store.Sessions()}
}
func (s rotationSessionFailure) Delete(context.Context, string, string) error {
	return errors.New("injected session rotation failure")
}

func TestSideEffectsOneTransactionSessionRotation(t *testing.T) {
	f := newMFAFixture(t)
	_, state, csrf := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	appCode(t, rec)
	original := f.b.cookies[session.CookieName].Value
	f.h.Authz.Store = rotationCommitFailure{f.st}
	_, state, csrf = f.b.begin(t, "prompt", "login")
	rec = f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") != "" {
		t.Error("code issued despite rotation failure")
	}
	if got := f.b.cookies[session.CookieName]; got == nil || got.Value != original {
		t.Error("failed rotation replaced SSO cookie")
	}
	rows, err := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
	if err != nil || len(rows) != 1 {
		t.Error("failed rotation changed sessions", rows, err)
	}
	u, err := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	if err != nil || u.LoginsCount != 1 {
		t.Error("failed rotation recorded login", u, err)
	}
}
