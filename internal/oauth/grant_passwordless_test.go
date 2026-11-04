package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

type pwlMail struct {
	mu   sync.Mutex
	last email.PasswordlessEmail
}

func (m *pwlMail) SendPasswordless(_ context.Context, e email.PasswordlessEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = e
	return nil
}

type pwlSMS struct{ last phone.Message }

func (s *pwlSMS) Send(_ context.Context, _ string, _ phone.Route, m phone.Message) (phone.Result, error) {
	s.last = m
	return phone.Result{}, nil
}

type safeRecorder struct {
	mu     sync.Mutex
	events []logs.Event
}

func (r *safeRecorder) Record(_ context.Context, e logs.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *safeRecorder) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.Type)
	}
	return out
}

func (r *safeRecorder) has(typ string) bool {
	for _, t := range r.types() {
		if t == typ {
			return true
		}
	}
	return false
}

type pwlFixture struct {
	*fixture
	tid  string
	mail *pwlMail
	sms  *pwlSMS
	rec  *safeRecorder
}

// newPasswordlessFixture adds the email and sms connections and two clients
// holding the passwordless OTP grant: "pwl" (confidential, secret pwl-secret)
// and "pwl-public" (no authentication).
func newPasswordlessFixture(t *testing.T) *pwlFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	ropg, err := f.st.Clients().Get(ctx, tid, "ropg")
	if err != nil {
		t.Fatal(err)
	}
	confV := *ropg
	conf := &confV
	conf.ClientID, conf.Name = "pwl", "Passwordless"
	conf.GrantTypes = []string{clientrules.GrantPasswordlessOTP, clientrules.GrantRefreshToken}
	conf.Callbacks = []string{"https://pwl.acme.test/cb"}
	sealed, err := keys.SealClientSecret(f.wrapper, tid, "pwl", "pwl-secret")
	if err != nil {
		t.Fatal(err)
	}
	conf.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: fixedNow()}}
	publicV := *ropg
	public := &publicV
	public.ClientID, public.Name = "pwl-public", "Passwordless public"
	public.TokenEndpointAuthMethod, public.Secrets = store.AuthMethodNone, nil
	public.GrantTypes = []string{clientrules.GrantPasswordlessOTP}
	for _, c := range []*store.Client{conf, public} {
		if err := f.st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Connection{
		{TenantID: tid, ID: "con_pwl_email", Name: "email", Strategy: "email", EnabledClients: []string{"pwl", "pwl-public", "ropg"}, BruteForceProtection: true},
		{TenantID: tid, ID: "con_pwl_sms", Name: "sms", Strategy: "sms", EnabledClients: []string{"pwl", "pwl-public", "ropg"}, BruteForceProtection: true},
	} {
		if err := f.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	p := &pwlFixture{fixture: f, tid: tid, mail: &pwlMail{}, sms: &pwlSMS{}, rec: &safeRecorder{}}
	f.h.Recorder = p.rec
	f.h.Passwordless = &passwordless.Service{Store: f.st, Wrapper: f.wrapper, SMS: p.sms, Email: p.mail, Recorder: p.rec, Now: fixedNow, Database: f.h.Database}
	return p
}

// startServer is POST /passwordless/start behind tenant resolution and the
// contract.
func (f *pwlFixture) start(t *testing.T, body string, header map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.PasswordlessStart))
	req := httptest.NewRequest("POST", "https://acme.example.test/passwordless/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	contract.WrapResponses(t, h).ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (f *pwlFixture) emailCode(t *testing.T, client, secret, addr string) string {
	t.Helper()
	body := map[string]any{"client_id": client, "connection": "email", "email": addr, "send": "code"}
	if secret != "" {
		body["client_secret"] = secret
	}
	raw, _ := json.Marshal(body)
	if rec, b := f.start(t, string(raw), nil); rec.Code != 200 {
		t.Fatalf("start = %d %v", rec.Code, b)
	}
	return f.mail.last.Code
}

func otpForm(client, secret, realm, username, otp string, extra ...string) url.Values {
	v := url.Values{"grant_type": {clientrules.GrantPasswordlessOTP}, "client_id": {client}, "realm": {realm}, "username": {username}, "otp": {otp}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func (f *pwlFixture) setFlag(t *testing.T, on bool) {
	t.Helper()
	tn, err := f.st.Tenants().Get(context.Background(), f.tid)
	if err != nil {
		t.Fatal(err)
	}
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["flags"] = map[string]any{"enforce_client_authentication_on_passwordless_start": on}
	if err := f.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
}

func TestStartClientAuthEnforced(t *testing.T) {
	f := newPasswordlessFixture(t)
	f.setFlag(t, true)
	if rec, b := f.start(t, `{"client_id":"pwl","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 401 || b["error"] != "invalid_client" {
		t.Fatalf("unauthenticated confidential = %d %v", rec.Code, b)
	}
	if rec, b := f.start(t, `{"client_id":"pwl","client_secret":"wrong","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 401 || b["error"] != "invalid_client" {
		t.Fatalf("wrong secret = %d %v", rec.Code, b)
	}
	if rec, b := f.start(t, `{"client_id":"pwl","client_secret":"pwl-secret","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 200 || b["email"] != "ada@acme.test" {
		t.Fatalf("authenticated confidential = %d %v", rec.Code, b)
	}
	if rec, b := f.start(t, `{"client_id":"pwl-public","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 200 {
		t.Fatalf("public = %d %v", rec.Code, b)
	}
	if f.rec.has("depnote") {
		t.Fatal("depnote with the flag on")
	}
	// With the flag off an unauthenticated confidential call is accepted
	// and logs depnote.
	f.setFlag(t, false)
	if rec, b := f.start(t, `{"client_id":"pwl","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 200 {
		t.Fatalf("flag off = %d %v", rec.Code, b)
	}
	if !f.rec.has("depnote") {
		t.Fatal("depnote not logged")
	}
	if rec, b := f.start(t, `{"client_id":"nobody","connection":"email","email":"ada@acme.test"}`, nil); rec.Code != 401 || b["error"] != "invalid_client" {
		t.Fatalf("unknown client = %d %v", rec.Code, b)
	}
}

// auth0.js forwards extra options; Auth0 ignores unknown start fields.
func TestStartAcceptsUnknownFields(t *testing.T) {
	f := newPasswordlessFixture(t)
	rec, b := f.start(t, `{"client_id":"pwl-public","connection":"sms","phone_number":"+14155550123","send":"code","xRequestLanguage":"en","authParams":{"scope":"openid","nested":{"a":1}},"unknown":{"x":true}}`, nil)
	if rec.Code != 200 || b["phone_number"] != "+14155550123" || len(b["_id"].(string)) != 24 {
		t.Fatalf("start = %d %v", rec.Code, b)
	}
	if rec, b := f.start(t, `not json`, nil); rec.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("bad body = %d %v", rec.Code, b)
	}
	if rec, b := f.start(t, `{"client_id":"pwl-public","connection":"sms","phone_number":"+14155550123","send":"code"}`, map[string]string{"x-request-language": "fr"}); rec.Code != 200 || f.sms.last.Locale != "fr" {
		t.Fatalf("language = %d %v %q", rec.Code, b, f.sms.last.Locale)
	}
}

func TestPasswordlessGrantIssuesTokens(t *testing.T) {
	f := newPasswordlessFixture(t)
	code := f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "Ada@Acme.test", code, "audience", acmeAPI, "scope", "openid read:things offline_access")})
	if rec.Code != 200 {
		t.Fatalf("grant = %d %v", rec.Code, b)
	}
	at, _ := verifyToken(t, f.keys, f.tid, b["access_token"].(string))
	if !strings.HasPrefix(at["sub"].(string), "email|") || at["azp"] != "pwl" {
		t.Fatalf("access token = %v", at)
	}
	if b["id_token"] == nil || b["refresh_token"] == nil {
		t.Fatalf("body = %v", b)
	}
	if !f.rec.has("s") || !f.rec.has("ss") || f.rec.has("fepotpft") {
		t.Fatalf("events = %v", f.rec.types())
	}
	// The code is single use.
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code)})
	if rec.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %v", rec.Code, b)
	}
	// redirect_uri is optional (P11) but validated when sent.
	code = f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code, "redirect_uri", "https://evil.test/cb")})
	if rec.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("bad redirect_uri = %d %v", rec.Code, b)
	}
	code = f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code, "redirect_uri", "https://pwl.acme.test/cb")})
	if rec.Code != 200 {
		t.Fatalf("allowed redirect_uri = %d %v", rec.Code, b)
	}
	// A client without the grant is refused before the code is touched.
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("ropg", "ropg-secret", "email", "ada@acme.test", "123456")})
	if rec.Code != 403 || b["error"] != "unauthorized_client" {
		t.Fatalf("no grant = %d %v", rec.Code, b)
	}
}

func TestPasswordlessGrantSMS(t *testing.T) {
	f := newPasswordlessFixture(t)
	if rec, b := f.start(t, `{"client_id":"pwl-public","connection":"sms","phone_number":"+14155550123","send":"code"}`, nil); rec.Code != 200 {
		t.Fatalf("start = %d %v", rec.Code, b)
	}
	rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "sms", "+14155550123", f.sms.last.Code, "scope", "openid")})
	if rec.Code != 200 {
		t.Fatalf("grant = %d %v", rec.Code, b)
	}
	// realm must match the connection the code was sent for.
	if rec, b := f.start(t, `{"client_id":"pwl-public","connection":"sms","phone_number":"+14155550123","send":"code"}`, nil); rec.Code != 200 {
		t.Fatalf("start = %d %v", rec.Code, b)
	}
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "+14155550123", f.sms.last.Code)})
	if rec.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("wrong realm = %d %v", rec.Code, b)
	}
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "nope", "+14155550123", f.sms.last.Code)})
	if rec.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("unknown realm = %d %v", rec.Code, b)
	}
}

func TestPasswordlessGrantSignupAndDisableSignup(t *testing.T) {
	f := newPasswordlessFixture(t)
	ctx := context.Background()
	code := f.emailCode(t, "pwl-public", "", "new@acme.test")
	conn, _ := f.st.Connections().GetByName(ctx, f.tid, "email")
	conn.DisableSignup = true
	if err := f.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "new@acme.test", code)})
	if rec.Code != 403 || b["error"] != "access_denied" {
		t.Fatalf("disable_signup grant = %d %v", rec.Code, b)
	}
	if !f.rec.has("fepotpft") || !f.rec.has("fu") {
		t.Fatalf("events = %v", f.rec.types())
	}
	if _, err := f.st.Users().FindByLogin(ctx, f.tid, "email", "new@acme.test"); err == nil {
		t.Fatal("user created with disable_signup")
	}
	// Start refuses unknown users while signup is disabled (P22).
	if rec, b := f.start(t, `{"client_id":"pwl-public","connection":"email","email":"new@acme.test","send":"code"}`, nil); rec.Code != 403 || b["error"] != "access_denied" {
		t.Fatalf("disable_signup start = %d %v", rec.Code, b)
	}
	conn.DisableSignup = false
	if err := f.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	code = f.emailCode(t, "pwl-public", "", "new@acme.test")
	if rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "new@acme.test", code)}); rec.Code != 200 {
		t.Fatalf("signup grant = %d %v", rec.Code, b)
	}
	u, err := f.st.Users().FindByLogin(ctx, f.tid, "email", "new@acme.test")
	if err != nil || !u.EmailVerified || u.Identities[0].Provider != "email" {
		t.Fatalf("created user = %+v %v", u, err)
	}
}

func TestPasswordlessGrantMFARequired(t *testing.T) {
	f := newPasswordlessFixture(t)
	ctx := context.Background()
	g, err := f.st.MFA().GetGuardian(ctx, f.tid)
	if err != nil {
		t.Fatal(err)
	}
	g.Factors = map[string]bool{"otp": true, "email": true, "recovery-code": true}
	g.Policies = []string{"all-applications"}
	if err := f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	f.h.MFA = mfa.NewService(f.st, f.wrapper, &mfaMail{}, nil, f.h.Log, fixedNow)
	f.addGrant(t, "pwl", otpGrant)
	code := f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b := f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code, "scope", "openid")})
	if rec.Code != 403 || b["error"] != "mfa_required" || b["mfa_token"] == nil {
		t.Fatalf("policy MFA = %d %v", rec.Code, b)
	}
	if f.rec.has("fepotpft") || !f.rec.has("mfar") {
		t.Fatalf("events = %v", f.rec.types())
	}
	// MFA API audience rule: an enrolled user needs MFA for the MFA API even
	// without a policy.
	g, _ = f.st.MFA().GetGuardian(ctx, f.tid)
	g.Policies = nil
	if err := f.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	u, err := f.st.Users().FindByLogin(context.Background(), f.tid, "email", "ada@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: f.tid, UserID: u.UserID, ID: "email|dev_pwl", Type: "email", Email: "ada@acme.test", Confirmed: true, CreatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
	code = f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code, "audience", "https://acme.example.test/mfa/", "scope", "read:authenticators")})
	if rec.Code != 403 || b["error"] != "mfa_required" {
		t.Fatalf("MFA API audience = %d %v", rec.Code, b)
	}
	code = f.emailCode(t, "pwl", "pwl-secret", "ada@acme.test")
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl", "pwl-secret", "email", "ada@acme.test", code, "scope", "openid")})
	if rec.Code != 200 {
		t.Fatalf("no policy, ordinary audience = %d %v", rec.Code, b)
	}
}

func TestPasswordlessGrantBlockedUser(t *testing.T) {
	f := newPasswordlessFixture(t)
	code := f.emailCode(t, "pwl-public", "", "ada@acme.test")
	if rec, b := f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "ada@acme.test", code)}); rec.Code != 200 {
		t.Fatalf("first login = %d %v", rec.Code, b)
	}
	code = f.emailCode(t, "pwl-public", "", "ada@acme.test")
	u, _ := f.st.Users().FindByLogin(context.Background(), f.tid, "email", "ada@acme.test")
	u.Blocked = true
	if err := f.st.Users().Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "ada@acme.test", code)})
	if rec.Code != 403 || b["error"] != "access_denied" {
		t.Fatalf("blocked = %d %v", rec.Code, b)
	}
	if !f.rec.has("fepotpft") {
		t.Fatal("fepotpft not logged")
	}
}

func TestPasswordlessGrantRefusalLogsFepotpft(t *testing.T) {
	f := newPasswordlessFixture(t)
	f.emailCode(t, "pwl-public", "", "ada@acme.test")
	rec, b := f.call(t, true, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "ada@acme.test", "000000")})
	if rec.Code != 400 || b["error"] != "invalid_grant" || b["error_description"] != "Wrong email or verification code." {
		t.Fatalf("wrong code = %d %v", rec.Code, b)
	}
	if !f.rec.has("fepotpft") || f.rec.has("s") {
		t.Fatalf("events = %v", f.rec.types())
	}
	for _, e := range f.rec.events {
		if strings.Contains(e.Description, "000000") {
			t.Fatal("otp logged")
		}
	}
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "sms", "+14155550123", "000000")})
	if rec.Code != 400 || b["error_description"] != "Wrong phone number or verification code." {
		t.Fatalf("sms wrong code = %d %v", rec.Code, b)
	}
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "ada@acme.test", "")})
	if rec.Code != 400 || b["error"] != "invalid_request" {
		t.Fatalf("missing otp = %d %v", rec.Code, b)
	}
}

func TestPasswordlessGrantRunsActions(t *testing.T) {
	actionstest.RequireNode(t)
	f := newPasswordlessFixture(t)
	env := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = env.Engine
	f.h.Passwordless.Actions = env.Engine
	pre := env.Deploy(t, f.tid, actions.TriggerPreUserRegistration, "tag-signup", `exports.onExecutePreUserRegistration=async(event,api)=>{api.user.setAppMetadata('via', event.connection.strategy);};`)
	env.Bind(t, f.tid, actions.TriggerPreUserRegistration, pre)
	env.PostLogin(t, f.tid, "claim", `exports.onExecutePostLogin=async(event,api)=>{api.accessToken.setCustomClaim('https://acme.test/conn', event.connection.name);};`)
	code := f.emailCode(t, "pwl-public", "", "ada@acme.test")
	rec, b := f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "ada@acme.test", code, "audience", acmeAPI)})
	if rec.Code != 200 {
		t.Fatalf("grant = %d %v", rec.Code, b)
	}
	at, _ := verifyToken(t, f.keys, f.tid, b["access_token"].(string))
	if at["https://acme.test/conn"] != "email" {
		t.Fatalf("post-login claim = %v", at)
	}
	u, err := f.st.Users().FindByLogin(context.Background(), f.tid, "email", "ada@acme.test")
	if err != nil || u.AppMetadata["via"] != "email" {
		t.Fatalf("pre-registration effect = %+v %v", u, err)
	}
	// A denying pre-registration Action refuses the signup (fs).
	deny := env.Deploy(t, f.tid, actions.TriggerPreUserRegistration, "deny", `exports.onExecutePreUserRegistration=async(event,api)=>{api.access.deny('no_signup','Signups are closed');};`)
	env.Bind(t, f.tid, actions.TriggerPreUserRegistration, deny)
	code = f.emailCode(t, "pwl-public", "", "late@acme.test")
	rec, b = f.call(t, false, tokenCall{host: acmeHost, form: otpForm("pwl-public", "", "email", "late@acme.test", code)})
	if rec.Code != 403 || b["error_description"] != "Signups are closed" {
		t.Fatalf("denied signup = %d %v", rec.Code, b)
	}
	if !f.rec.has("fs") || !f.rec.has("fepotpft") {
		t.Fatalf("events = %v", f.rec.types())
	}
}

// Password flows never treat passwordless connections as databases.
func TestPasswordGrantRefusesPasswordlessRealm(t *testing.T) {
	f := newPasswordlessFixture(t)
	for _, realm := range []string{"email", "sms"} {
		form := pw("ropg", "ropg-secret", "ada@acme.test", "whatever password")
		form.Set("grant_type", GrantPasswordRealm)
		form.Set("realm", realm)
		rec, b := f.call(t, true, tokenCall{host: acmeHost, form: form})
		if rec.Code != 400 || b["error"] != "invalid_request" {
			t.Fatalf("realm %s = %d %v", realm, rec.Code, b)
		}
	}
}

func (f *pwlFixture) addGrant(t *testing.T, client string, grants ...string) {
	t.Helper()
	c, err := f.st.Clients().Get(context.Background(), f.tid, client)
	if err != nil {
		t.Fatal(err)
	}
	c.GrantTypes = append(c.GrantTypes, grants...)
	if err := f.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}
