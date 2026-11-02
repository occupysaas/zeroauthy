package login

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type mfaMail struct{ codes []string }

func (m *mfaMail) Send(_ context.Context, e email.Event) error {
	m.codes = append(m.codes, e.Variables["code"].(string))
	return nil
}

type mfaPages interface {
	MFAPage(http.ResponseWriter, *http.Request)
	MFASubmit(http.ResponseWriter, *http.Request)
	MFATicket(http.ResponseWriter, *http.Request)
}
type mfaFixture struct {
	*env
	b                *browser
	tn               *store.Tenant
	uid, state, csrf string
	mail             *mfaMail
	clock            *time.Time
}

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", aliceLogin)
	if err != nil {
		t.Fatal(err)
	}
	tn.SettingsExtra = map[string]any{}
	if tn.CustomText == nil {
		tn.CustomText = store.CustomText{}
	}
	u.EmailVerified = true
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	now := fixedNow()
	mail := &mfaMail{}
	e.h.Now = func() time.Time { return now }
	e.h.Authz.Now = e.h.Now
	e.h.Sessions.Now = e.h.Now
	e.h.Authz.Wrapper = w
	e.h.MFA = mfa.NewService(e.st, w, mail, nil, e.h.Log, e.h.Now)
	old := e.srv
	mux := http.NewServeMux()
	if h, ok := any(e.h).(mfaPages); ok {
		for _, p := range []string{"/u/mfa", "/u/mfa-otp-enrollment", "/u/mfa-otp-challenge", "/u/mfa-email-challenge", "/u/mfa-recovery-code-enrollment", "/u/mfa-recovery-code-challenge"} {
			mux.HandleFunc("GET "+p, h.MFAPage)
			mux.HandleFunc("POST "+p, h.MFASubmit)
		}
		mux.HandleFunc("GET /u/mfa-enroll-ticket", h.MFATicket)
	}
	mux.Handle("/", old)
	e.srv = tenant.NewResolver(e.st.Tenants(), "", false).Middleware(mux)
	return &mfaFixture{env: e, b: e.browser("acme.example.test"), tn: tn, uid: u.UserID, mail: mail, clock: &now}
}
func (f *mfaFixture) policy(t *testing.T, factors ...string) {
	t.Helper()
	g, err := f.st.MFA().GetGuardian(context.Background(), f.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	g.Factors = map[string]bool{"recovery-code": true}
	for _, v := range factors {
		g.Factors[v] = true
	}
	g.Policies = []string{"all-applications"}
	if err = f.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
}
func (f *mfaFixture) begin(t *testing.T) {
	t.Helper()
	_, s, c := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("gate %d %s %s", rec.Code, loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
}
func (f *mfaFixture) page(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := f.b.do(t, "GET", path+"?state="+f.state, nil)
	if r.Code == 303 {
		loc, _ := url.Parse(r.Header().Get("Location"))
		r = f.b.do(t, "GET", loc.RequestURI(), nil)
	}
	if r.Code != 200 {
		t.Fatalf("MFA page %s =%d %s", path, r.Code, r.Body)
	}
	if m := csrfField.FindStringSubmatch(r.Body.String()); m != nil {
		f.csrf = m[1]
	}
	return r
}
func (f *mfaFixture) post(t *testing.T, path string, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	v.Set("state", f.state)
	v.Set("csrf", f.csrf)
	return f.b.do(t, "POST", path, v)
}
func otpAt(secret string, now time.Time) string {
	k, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, k)
	h.Write(b[:])
	s := h.Sum(nil)
	i := s[19] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(s[i:i+4])&0x7fffffff)%1000000)
}
func (f *mfaFixture) enrolled(t *testing.T, factor string, preferred bool) string {
	t.Helper()
	e, err := f.h.MFA.BeginEnroll(context.Background(), f.tn.ID, f.uid, factor, f.b.host)
	if err != nil {
		t.Fatal(err)
	}
	code := otpAt(e.Secret, *f.clock)
	if factor == "email" {
		code = f.mail.codes[len(f.mail.codes)-1]
	}
	if _, err = f.h.MFA.ConfirmEnroll(context.Background(), f.tn.ID, f.uid, e, mfa.Proof{Code: code}); err != nil {
		t.Fatal(err)
	}
	if preferred {
		a, _ := f.st.MFA().GetAuthenticator(context.Background(), f.tn.ID, f.uid, e.AuthenticatorID)
		a.Preferred = true
		if err = f.st.MFA().UpdateAuthenticator(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	*f.clock = f.clock.Add(time.Minute)
	return e.Secret
}
func TestMFAOTPEnrollFlow(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	m := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
	if m == nil || !strings.Contains(p.Body.String(), "<svg") {
		t.Fatalf("missing secret/QR %s", p.Body)
	}
	r := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(m[1], *f.clock)}})
	recovery := regexp.MustCompile(`<code id="recovery-code">([A-Z0-9]{24})</code>`).FindStringSubmatch(r.Body.String())
	if recovery == nil {
		t.Fatalf("missing one-time recovery %d %s", r.Code, r.Body)
	}
	if c := f.b.cookies[session.CookieName]; c == nil {
		t.Fatal("missing first-factor session")
	}
	req := httptest.NewRequest("GET", "https://"+f.b.host+"/", nil)
	req.AddCookie(f.b.cookies[session.CookieName])
	sess, _ := f.h.Sessions.Lookup(context.Background(), req, f.tn)
	if !sess.MFAAt.IsZero() {
		t.Fatal("marked before acknowledgement")
	}
	p = f.page(t, "/u/mfa-recovery-code-enrollment")
	if strings.Contains(p.Body.String(), recovery[1]) {
		t.Fatal("recovery redisplayed")
	}
	r = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if !strings.Contains(r.Header().Get("Location"), "code=") {
		t.Fatalf("ack %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}
func TestMFAChallengePreferredFirst(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp", "email")
	f.enrolled(t, "otp", false)
	f.enrolled(t, "email", true)
	f.begin(t)
	r := f.b.do(t, "GET", "/u/mfa?state="+f.state, nil)
	if !strings.Contains(r.Header().Get("Location"), "mfa-email-challenge") {
		t.Fatalf("preferred %d %s", r.Code, r.Header().Get("Location"))
	}
}
func TestMFATryAnotherMethod(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp", "email")
	f.enrolled(t, "otp", true)
	f.enrolled(t, "email", false)
	f.begin(t)
	r := f.b.do(t, "GET", "/u/mfa?state="+f.state+"&action=another", nil)
	for _, v := range []string{"value=\"email\"", "value=\"recovery-code\""} {
		if !strings.Contains(r.Body.String(), v) {
			t.Fatalf("missing option %s %s", v, r.Body)
		}
	}
	r = f.post(t, "/u/mfa", url.Values{"factor": {"sms"}})
	if r.Code < 400 {
		t.Fatal("accepted stored factor")
	}
}
func TestMFAEmailResendAfter30s(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "email")
	f.enrolled(t, "email", false)
	f.begin(t)
	before := len(f.mail.codes)
	r := f.post(t, "/u/mfa-email-challenge", url.Values{"action": {"resend"}})
	if r.Code != 429 || len(f.mail.codes) != before {
		t.Fatalf("early resend %d %d", r.Code, len(f.mail.codes))
	}
	*f.clock = f.clock.Add(30 * time.Second)
	r = f.post(t, "/u/mfa-email-challenge", url.Values{"action": {"resend"}})
	if r.Code != 200 || len(f.mail.codes) != before+1 {
		t.Fatalf("resend %d %s", r.Code, r.Body)
	}
}
func TestMFARememberBrowserCookie(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp")
			secret := f.enrolled(t, "otp", false)
			f.begin(t)
			f.setRemember(t, allow)
			p := f.page(t, "/u/mfa-otp-challenge")
			if strings.Contains(p.Body.String(), `name="remember"`) != allow {
				t.Fatal("remember visibility")
			}
			r := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}, "remember": {"yes"}})
			found := false
			for _, c := range r.Result().Cookies() {
				if c.Name == session.MFARememberCookie {
					found = true
					if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Domain != "" {
						t.Fatalf("cookie %+v", c)
					}
				}
			}
			if found != allow {
				t.Fatalf("remember cookie present=%v allow=%v", found, allow)
			}
			if r.Code != 302 {
				t.Fatalf("verify %d %s", r.Code, r.Body)
			}
		})
	}
}
func TestMFAPageWithoutRequirementRedirects(t *testing.T) {
	f := newMFAFixture(t)
	_, s, _ := f.b.begin(t)
	r := f.b.do(t, "GET", "/u/mfa?state="+s, nil)
	if r.Code != 303 || !strings.Contains(r.Header().Get("Location"), "/authorize/resume?error=invalid_request") {
		t.Fatalf("unexpected %d %s", r.Code, r.Header().Get("Location"))
	}
}
func TestMFACSRF(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	f.begin(t)
	r := f.b.do(t, "POST", "/u/mfa-otp-enrollment", url.Values{"state": {f.state}, "csrf": {"wrong"}, "code": {"000000"}})
	if r.Code < 400 {
		t.Fatal("accepted bad CSRF")
	}
}
func TestMFACustomTextApplies(t *testing.T) {
	f := newMFAFixture(t)
	f.tn.CustomText["mfa-otp"] = map[string]map[string]map[string]string{"en": {"mfa-otp-enrollment-qr": {"title": "Custom MFA heading"}}}
	c, err := f.st.HostedLogins().Get(context.Background(), f.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.CustomText = f.tn.CustomText.Clone()
	if err = f.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	if !strings.Contains(p.Body.String(), "Custom MFA heading") {
		t.Fatalf("override absent %s", p.Body)
	}
}
func TestMFAShowFactorListFlag(t *testing.T) {
	f := newMFAFixture(t)
	f.tn.SettingsExtra["mfa_show_factor_list_on_enrollment"] = true
	if err := f.st.Tenants().Update(context.Background(), f.tn); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa")
	if !strings.Contains(p.Body.String(), `value="otp"`) {
		t.Fatalf("factor list absent %s", p.Body)
	}
}
func TestMFALocalized(t *testing.T) {
	f := newMFAFixture(t)
	f.b.acceptLanguage = "fr"
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	if !strings.Contains(p.Body.String(), "authentification") {
		t.Fatalf("French absent %s", p.Body)
	}
}
func TestMFAOTPConcurrentSubmit(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", false)
	f.begin(t)
	var wg sync.WaitGroup
	out := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := *f.b
			b.cookies = map[string]*http.Cookie{}
			for k, v := range f.b.cookies {
				b.cookies[k] = v
			}
			b.formRevisions = map[string]string{}
			for k, v := range f.b.formRevisions {
				b.formRevisions[k] = v
			}
			r := b.send("POST", "/u/mfa-otp-challenge", url.Values{"state": {f.state}, "csrf": {f.csrf}, "code": {otpAt(secret, *f.clock)}})
			out <- r.Code
		}()
	}
	wg.Wait()
	close(out)
	success := 0
	for c := range out {
		if c == 302 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successes=%d", success)
	}
}
func TestMFATicketEnrollNoPassword(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	raw := secrets.RandomString(32)
	if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, Hash: secrets.HashToken(raw), UserID: f.uid, Factor: "otp", ExpiresAt: f.clock.Add(7 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	if r.Code != 303 || f.b.cookies[session.CookieName] != nil {
		t.Fatalf("ticket %d %s", r.Code, r.Body)
	}
	r = f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	if r.Code < 400 {
		t.Fatal("reused ticket")
	}
	raw = secrets.RandomString(32)
	_ = f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, Hash: secrets.HashToken(raw), UserID: f.uid, Factor: "otp", ExpiresAt: f.clock.Add(7 * 24 * time.Hour)})
	*f.clock = f.clock.Add(7 * 24 * time.Hour)
	r = f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	if r.Code < 400 {
		t.Fatal("expired ticket")
	}
}

// Modify only the already sealed test authority to exercise both gate contracts.
func (f *mfaFixture) setRemember(t *testing.T, allow bool) {
	t.Helper()
	ctx := context.Background()
	txn, err := f.st.AuthTransactions().Get(ctx, f.tn.ID, f.state)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://"+f.b.host+"/", nil)
	for _, c := range f.b.cookies {
		r.AddCookie(c)
	}
	res := tenant.Resolved{Tenant: f.tn} // use resolver to retain exact host/origin binding
	var pending []byte
	handler := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		res, _ = tenant.FromContext(r.Context())
		sess, e := f.h.Authz.ActiveSession(ctx, r, res)
		if e != nil {
			t.Fatal(e)
		}
		p, e := f.h.Authz.PendingMFA(ctx, r, res, txn, sess)
		if e != nil {
			t.Fatal(e)
		}
		p.Requirement.AllowRemember = allow
		pending, _ = json.Marshal(p)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), r)
	sealed, err := keys.SealBound(f.h.Authz.Wrapper, "hosted-mfa/v1", []string{f.tn.ID, txn.ID, txn.Params["za_session"], txn.ClientID, res.Origin()}, pending)
	if err != nil {
		t.Fatal(err)
	}
	txn.Params["za_mfa_pending"] = base64.RawURLEncoding.EncodeToString(sealed)
	if err = f.st.AuthTransactions().Delete(ctx, f.tn.ID, txn.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.st.AuthTransactions().Create(ctx, txn); err != nil {
		t.Fatal(err)
	}
}

func TestMFATicketProofNeverCreatesSSO(t *testing.T) {
	f := newMFAFixture(t)
	c, err := f.st.HostedLogins().Get(context.Background(), f.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.CustomText["mfa"] = map[string]map[string]map[string]string{"en": {"mfa-enroll-result": {"title": "Custom ticket success"}}}
	c.Partials = map[string]map[string]map[string]string{"mfa": {"mfa-enroll-result": {"form-content-start": "<p>Ticket result partial</p>"}}}
	if err = f.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "otp")
	g, _ := f.st.MFA().GetGuardian(context.Background(), f.tn.ID)
	g.Policies = nil
	if err := f.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	raw := secrets.RandomString(32)
	if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: "otp", ExpiresAt: f.clock.Add(7 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	f.state = loc.Query().Get("state")
	p := f.page(t, "/u/mfa")
	secret := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
	if secret == nil {
		t.Fatalf("ticket did not enroll %d", p.Code)
	}
	r = f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(secret[1], *f.clock)}})
	if !strings.Contains(r.Body.String(), `id="recovery-code"`) {
		t.Fatalf("ticket proof %d", r.Code)
	}
	r = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Enrollment complete") {
		t.Fatalf("ticket result %d %s", r.Code, r.Body)
	}
	if !strings.Contains(r.Body.String(), "Custom ticket success") || !strings.Contains(r.Body.String(), "Ticket result partial") {
		t.Fatal("ticket result lost custom text or partial")
	}
	if f.b.cookies[session.CookieName] != nil || strings.Contains(r.Header().Get("Location"), "code=") {
		t.Fatal("ticket established authentication")
	}
	r = f.b.do(t, "GET", "/authorize?client_id=spa&response_type=code&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcb&scope=openid&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	if !strings.HasPrefix(r.Header().Get("Location"), "/u/login?") {
		t.Fatalf("ticket bypassed first factor: %s", r.Header().Get("Location"))
	}
}
func TestMFAEmailFiveSendLimit(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "email")
	f.enrolled(t, "email", false)
	f.begin(t)
	for len(f.mail.codes) < 5 {
		*f.clock = f.clock.Add(30 * time.Second)
		if r := f.post(t, "/u/mfa-email-challenge", url.Values{"action": {"resend"}}); r.Code != 200 {
			t.Fatalf("send %d", r.Code)
		}
	}
	*f.clock = f.clock.Add(30 * time.Second)
	if r := f.post(t, "/u/mfa-email-challenge", url.Values{"action": {"resend"}}); r.Code != 429 || len(f.mail.codes) != 5 {
		t.Fatalf("limit %d sends=%d", r.Code, len(f.mail.codes))
	}
}
func TestMFAEmailEnrollFlow(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "email")
	f.begin(t)
	r := f.post(t, "/u/mfa-email-challenge", url.Values{"code": {f.mail.codes[len(f.mail.codes)-1]}})
	if !strings.Contains(r.Body.String(), `id="recovery-code"`) {
		t.Fatalf("enrollment %d", r.Code)
	}
	r = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if r.Code != 302 {
		t.Fatalf("ack %d %s", r.Code, r.Body)
	}
}
func TestMFARecoveryChallenge(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	e, err := f.h.MFA.BeginEnroll(context.Background(), f.tn.ID, f.uid, "otp", f.b.host)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := f.h.MFA.ConfirmEnroll(context.Background(), f.tn.ID, f.uid, e, mfa.Proof{Code: otpAt(e.Secret, *f.clock)})
	if err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(time.Minute)
	f.begin(t)
	f.page(t, "/u/mfa-recovery-code-challenge")
	r := f.post(t, "/u/mfa-recovery-code-challenge", url.Values{"code": {confirmed.RecoveryCode}})
	if !strings.Contains(r.Body.String(), `id="recovery-code"`) {
		t.Fatalf("recovery %d", r.Code)
	}
	r = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if r.Code != 302 {
		t.Fatalf("recovery ack %d", r.Code)
	}
}
func TestMFAPartialsApplyAndCapture(t *testing.T) {
	f := newMFAFixture(t)
	c, err := f.st.HostedLogins().Get(context.Background(), f.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Partials = map[string]map[string]map[string]string{"mfa-otp": {"mfa-otp-enrollment-qr": {"form-content-start": `<label>MFA note<input name="ulp-mfa-note" value="hello"></label>`}}}
	if err = f.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	if !strings.Contains(p.Body.String(), "MFA note") {
		t.Fatal("partial absent")
	}
	r := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {"000000"}, "ulp-mfa-note": {"saved"}})
	if r.Code != 400 {
		t.Fatalf("invalid proof %d", r.Code)
	}
	txn, _ := f.st.AuthTransactions().Get(context.Background(), f.tn.ID, f.state)
	if txn.HostedState.PromptFields["ulp-mfa-note"] != "saved" {
		t.Fatalf("fields %v", txn.HostedState.PromptFields)
	}
}

func (f *mfaFixture) ticketOTP(t *testing.T, multiple bool) string {
	t.Helper()
	raw := secrets.RandomString(32)
	if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: "otp", AllowMultiple: multiple, ExpiresAt: f.clock.Add(7 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	if r.Code != 303 {
		t.Fatalf("ticket %d", r.Code)
	}
	f.state = loc.Query().Get("state")
	p := f.page(t, "/u/mfa")
	m := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
	if m == nil {
		t.Fatal("missing ticket OTP")
	}
	return m[1]
}
func TestMFATicketConcurrentNoMultiple(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	second := *f
	second.b = f.env.browser(f.b.host)
	a := f.ticketOTP(t, false)
	b := second.ticketOTP(t, false)
	out := make(chan int, 2)
	var wg sync.WaitGroup
	for i, fixture := range []*mfaFixture{f, &second} {
		wg.Add(1)
		go func(i int, fixture *mfaFixture) {
			defer wg.Done()
			secret := a
			if i == 1 {
				secret = b
			}
			r := fixture.b.send("POST", "/u/mfa-otp-enrollment", url.Values{"state": {fixture.state}, "csrf": {fixture.csrf}, "code": {otpAt(secret, *fixture.clock)}})
			out <- r.Code
		}(i, fixture)
	}
	wg.Wait()
	close(out)
	success := 0
	for code := range out {
		if code == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("ticket successes %d", success)
	}
	third := *f
	third.b = f.env.browser(f.b.host)
	secret := third.ticketOTP(t, true)
	r := third.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(secret, *third.clock)}})
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Enrollment complete") {
		t.Fatalf("allow multiple %d", r.Code)
	}
}
func TestMFAEmailEnrollmentLogs(t *testing.T) {
	f := newMFAFixture(t)
	capture := &eventRecorder{}
	f.h.Recorder = capture
	f.h.MFA.Recorder = capture
	old := f.srv
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		old.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), capture)))
	})
	f.policy(t, "email")
	f.begin(t)
	r := f.post(t, "/u/mfa-email-challenge", url.Values{"code": {f.mail.codes[len(f.mail.codes)-1]}})
	if r.Code != 200 {
		t.Fatalf("email enrollment %d", r.Code)
	}
	for _, code := range []string{"mfar", "gd_send_email_verification", "gd_auth_email_verification"} {
		found := false
		for _, e := range capture.events {
			if e.Type == code && e.TenantID == f.tn.ID && e.UserID == f.uid {
				found = true
			}
		}
		if !found {
			t.Errorf("missing emitted %s", code)
		}
	}
}
func TestMFABrowserBindingAndTicketFactor(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp", "email")
	f.ticketOTP(t, false)
	other := f.env.browser(f.b.host)
	r := other.do(t, "GET", "/u/mfa-otp-enrollment?state="+f.state, nil)
	if r.Code != 303 || !strings.Contains(r.Header().Get("Location"), "invalid_request") {
		t.Fatalf("cookie binding %d", r.Code)
	}
	r = f.b.do(t, "GET", "/u/mfa-email-challenge?state="+f.state, nil)
	if r.Code < 400 {
		t.Fatalf("ticket factor widened %d", r.Code)
	}
}
