package passwordless

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fakeSMS struct {
	mu   sync.Mutex
	msgs []phone.Message
	err  error
}

func (f *fakeSMS) Send(_ context.Context, _ string, r phone.Route, m phone.Message) (phone.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Purpose != "passwordless" || r.ConnectionID == "" {
		return phone.Result{}, errors.New("bad route")
	}
	f.msgs = append(f.msgs, m)
	return phone.Result{}, f.err
}

func (f *fakeSMS) last(t *testing.T) phone.Message {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatal("no SMS sent")
	}
	return f.msgs[len(f.msgs)-1]
}

type fakeEmail struct {
	mu   sync.Mutex
	msgs []email.PasswordlessEmail
}

func (f *fakeEmail) SendPasswordless(_ context.Context, m email.PasswordlessEmail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakeEmail) last(t *testing.T) email.PasswordlessEmail {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatal("no email sent")
	}
	return f.msgs[len(f.msgs)-1]
}

type recorder struct {
	mu     sync.Mutex
	events []logs.Event
}

func (r *recorder) Record(_ context.Context, e logs.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) of(typ string) []logs.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logs.Event
	for _, e := range r.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

type testEnv struct {
	t     *testing.T
	ctx   context.Context
	st    *memory.Store
	sms   *fakeSMS
	mail  *fakeEmail
	rec   *recorder
	svc   *Service
	clock atomic.Int64
	// jar is the default browser's cookies for serve.
	jar map[string]*http.Cookie
}

const tid = "t1"

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	p := protectionrules.Defaults()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: "acme", FriendlyName: "Acme", SettingsExtra: map[string]any{},
		ProtectionSettings: p, ProtectionSettingsInitialized: true}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*store.Client{
		{TenantID: tid, ClientID: "cli", Name: "Portal", IsFirstParty: true, AppType: "spa", TokenEndpointAuthMethod: store.AuthMethodNone, GrantTypes: []string{clientrules.GrantPasswordlessOTP, clientrules.GrantAuthorizationCode}, Callbacks: []string{"https://app.test/cb"}},
		{TenantID: tid, ClientID: "nogrant", Name: "No grant", IsFirstParty: true, TokenEndpointAuthMethod: store.AuthMethodNone, GrantTypes: []string{clientrules.GrantAuthorizationCode}},
		{TenantID: tid, ClientID: "other", Name: "Other", IsFirstParty: true, TokenEndpointAuthMethod: store.AuthMethodNone, GrantTypes: []string{clientrules.GrantPasswordlessOTP}},
	} {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Connection{
		{TenantID: tid, ID: "con_email", Name: "email", Strategy: "email", EnabledClients: []string{"cli", "nogrant"}, BruteForceProtection: true},
		{TenantID: tid, ID: "con_sms", Name: "sms", Strategy: "sms", EnabledClients: []string{"cli"}, BruteForceProtection: true},
	} {
		if err := st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, ctx: ctx, st: st, sms: &fakeSMS{}, mail: &fakeEmail{}, rec: &recorder{}}
	e.clock.Store(testNow.UnixNano())
	now := func() time.Time { return time.Unix(0, e.clock.Load()).UTC() }
	e.svc = &Service{Store: st, Wrapper: w, SMS: e.sms, Email: e.mail, Recorder: e.rec, Now: now}
	e.ctx = WithRequest(ctx, RequestInfo{IP: "203.0.113.9", UserAgent: "test"})
	return e
}

func (e *testEnv) advance(d time.Duration) { e.clock.Add(int64(d)) }

func (e *testEnv) start(in StartInput) (*StartResult, error) {
	in.TenantID = tid
	if in.ClientID == "" {
		in.ClientID = "cli"
	}
	if in.IP == "" {
		in.IP = "203.0.113.9"
	}
	if in.Origin == "" {
		in.Origin = "https://acme.example.test"
	}
	return e.svc.Start(e.ctx, in)
}

func (e *testEnv) emailCode(addr string) string {
	e.t.Helper()
	if _, err := e.start(StartInput{Connection: "email", Email: addr, Send: "code"}); err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return e.mail.last(e.t).Code
}

func (e *testEnv) smsCode(number string) string {
	e.t.Helper()
	if _, err := e.start(StartInput{Connection: "sms", PhoneNumber: number, Send: "code"}); err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return e.sms.last(e.t).Code
}

func wantError(t *testing.T, err error, status int, code string) *Error {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != status || pe.Code != code {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
	return pe
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func TestStartEmailCode(t *testing.T) {
	e := newTestEnv(t)
	res, err := e.start(StartInput{Connection: "email", Email: " Ada@Example.TEST ", Send: "code", Locale: "fr"})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{24}$`).MatchString(res.ID) || res.Email != "ada@example.test" || res.Verified {
		t.Fatalf("result = %+v", res)
	}
	m := e.mail.last(t)
	if m.To != "ada@example.test" || !sixDigits.MatchString(m.Code) || m.Link != "" || m.Language != "fr" || m.ClientID != "cli" {
		t.Fatalf("email = %+v", m)
	}
	cs := e.rec.of("cs")
	if len(cs) != 1 || cs[0].UserName != "ada@example.test" || cs[0].Connection != "email" || cs[0].ClientID != "cli" {
		t.Fatalf("cs = %+v", cs)
	}
	u, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", m.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^email\|[0-9a-f]{24}$`).MatchString(u.UserID) || u.Email != "ada@example.test" || !u.EmailVerified ||
		len(u.Identities) != 1 || u.Identities[0].Provider != "email" || u.Identities[0].Connection != "email" {
		t.Fatalf("user = %+v", u)
	}
	if len(e.rec.of("ss")) != 1 {
		t.Fatal("ss not logged on creation")
	}
	// The second login finds the same user.
	again, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", e.emailCode("ada@example.test"))
	if err != nil || again.UserID != u.UserID || len(e.rec.of("ss")) != 1 {
		t.Fatalf("second login = %v %v", again, err)
	}
}

func TestStartSMSCode(t *testing.T) {
	e := newTestEnv(t)
	res, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.PhoneNumber != "+14155550123" {
		t.Fatalf("result = %+v", res)
	}
	m := e.sms.last(t)
	if m.To != "+14155550123" || m.Type != "passwordless" || !sixDigits.MatchString(m.Code) || m.ClientID != "cli" || m.DeliveryMethod != "text" {
		t.Fatalf("sms = %+v", m)
	}
	cs := e.rec.of("cs")
	if len(cs) != 1 || cs[0].UserName != phone.Mask("+14155550123") || strings.Contains(cs[0].UserName, "4155550123") {
		t.Fatalf("cs = %+v", cs)
	}
	for _, ev := range e.rec.events {
		if strings.Contains(ev.UserName+ev.Description, "4155550123") || strings.Contains(ev.UserName, m.Code) {
			t.Fatalf("full number or code logged: %+v", ev)
		}
	}
	u, err := e.svc.VerifyCode(e.ctx, tid, "cli", "sms", "+14155550123", m.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.UserID, "sms|") || u.PhoneNumber != "+14155550123" || !u.PhoneVerified || u.PhoneNormalized != "+14155550123" {
		t.Fatalf("user = %+v", u)
	}
	// A delivery failure logs fn and answers sms_provider_error.
	e.sms.err = &phone.SendError{Class: phone.ClassProviderAuth, Err: phone.ErrNoProvider}
	_, err = e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550124"})
	wantError(t, err, 400, "sms_provider_error")
	if len(e.rec.of("fn")) != 1 {
		t.Fatal("fn not logged")
	}
}

func TestStartLink(t *testing.T) {
	e := newTestEnv(t)
	params := url.Values{"redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}}
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test", AuthParams: params}); err != nil {
		t.Fatal(err)
	}
	m := e.mail.last(t)
	if m.Code != "" || !strings.HasPrefix(m.Link, "https://acme.example.test/passwordless/verify_redirect?") {
		t.Fatalf("link email = %+v", m)
	}
	link, _ := url.Parse(m.Link)
	token := link.Query().Get("verification_code")
	if len(token) != 43 || link.Query().Get("client_id") != "cli" || link.Query().Get("connection") != "email" {
		t.Fatalf("link = %s", m.Link)
	}
	if cls := e.rec.of("cls"); len(cls) != 1 || cls[0].UserName != "ada@example.test" || len(e.rec.of("cs")) != 0 {
		t.Fatalf("cls = %+v", cls)
	}
	// SMS has no links.
	_, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123", Send: "link"})
	wantError(t, err, 400, "invalid_request")
	// The sealed authParams come back with the link.
	row, got, err := e.svc.PeekLink(e.ctx, tid, token)
	if err != nil || row.ClientID != "cli" || got.Get("state") != "s1" || got.Get("client_id") != "cli" || got.Get("redirect_uri") != "https://app.test/cb" {
		t.Fatalf("peek = %+v %v %v", row, got, err)
	}
}

func TestStartRequiresEnabledConnection(t *testing.T) {
	e := newTestEnv(t)
	// The sms connection is not enabled for "other".
	_, err := e.start(StartInput{ClientID: "other", Connection: "sms", PhoneNumber: "+14155550123"})
	wantError(t, err, 400, "invalid_request")
	_, err = e.start(StartInput{Connection: "nope", Email: "ada@example.test"})
	wantError(t, err, 400, "invalid_request")
	// The client must hold the passwordless OTP grant.
	_, err = e.start(StartInput{ClientID: "nogrant", Connection: "email", Email: "ada@example.test"})
	wantError(t, err, 403, "unauthorized_client")
	_, err = e.start(StartInput{Connection: "email", Email: "not-an-email"})
	wantError(t, err, 400, "invalid_request")
	_, err = e.start(StartInput{Connection: "sms", PhoneNumber: "4155550123"})
	wantError(t, err, 400, "invalid_request")
	// disable_signup refuses unknown users at start (P22) and blocked users get nothing.
	conn, _ := e.st.Connections().GetByName(e.ctx, tid, "email")
	conn.DisableSignup = true
	if err := e.st.Connections().Update(e.ctx, conn); err != nil {
		t.Fatal(err)
	}
	_, err = e.start(StartInput{Connection: "email", Email: "new@example.test", Send: "code"})
	wantError(t, err, 403, "access_denied")
	if len(e.mail.msgs) != 0 {
		t.Fatal("message sent to refused identifier")
	}
}

func TestStartBlockedUserGetsNoMessage(t *testing.T) {
	e := newTestEnv(t)
	u, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", e.emailCode("ada@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	u.Blocked = true
	if err := e.st.Users().Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	n := len(e.mail.msgs)
	_, err = e.start(StartInput{Connection: "email", Email: "ada@example.test", Send: "code"})
	wantError(t, err, 403, "access_denied")
	if len(e.mail.msgs) != n {
		t.Fatal("blocked user was sent a message")
	}
}

func TestStartCountryCodes(t *testing.T) {
	e := newTestEnv(t)
	set := func(mode string, list ...string) {
		tn, _ := e.st.Tenants().Get(e.ctx, tid)
		l := []any{}
		for _, c := range list {
			l = append(l, c)
		}
		tn.SettingsExtra["country_codes"] = map[string]any{"mode": mode, "list": l}
		if err := e.st.Tenants().Update(e.ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	set("deny", "US")
	_, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"})
	wantError(t, err, 400, "invalid_request")
	if _, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+447700900123"}); err != nil {
		t.Fatalf("GB under deny US: %v", err)
	}
	set("allow", "GB")
	_, err = e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"})
	wantError(t, err, 400, "invalid_request")
	if _, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+447700900124"}); err != nil {
		t.Fatalf("GB under allow GB: %v", err)
	}
	if len(e.sms.msgs) != 2 {
		t.Fatalf("sent %d messages", len(e.sms.msgs))
	}
}

func TestStartSendBudget(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < 10; i++ {
		if _, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	_, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"})
	if pe := wantError(t, err, 429, "too_many_requests"); pe.RetryAfter <= 0 {
		t.Fatalf("retry after = %d", pe.RetryAfter)
	}
	lp := e.rec.of("limit_phone")
	if len(lp) != 1 || lp[0].Details["retry_after_seconds"] == nil || strings.Contains(lp[0].UserName, "4155550123") {
		t.Fatalf("limit_phone = %+v", lp)
	}
	if len(e.sms.msgs) != 10 {
		t.Fatalf("sent %d", len(e.sms.msgs))
	}
	// An hour later the identifier budget is back.
	e.advance(time.Hour + time.Second)
	if _, err := e.start(StartInput{Connection: "sms", PhoneNumber: "+14155550123"}); err != nil {
		t.Fatal(err)
	}

	// Per IP: 50 starts an hour across identifiers.
	e = newTestEnv(t)
	for i := 0; i < 50; i++ {
		if _, err := e.start(StartInput{Connection: "email", Email: "u" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@example.test", Send: "code", IP: "198.51.100.7"}); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	_, err = e.start(StartInput{Connection: "email", Email: "last@example.test", Send: "code", IP: "198.51.100.7"})
	wantError(t, err, 429, "too_many_requests")
	if len(e.rec.of("api_limit")) != 1 {
		t.Fatal("api_limit not logged")
	}
	// Another IP is unaffected.
	if _, err := e.start(StartInput{Connection: "email", Email: "last@example.test", Send: "code", IP: "198.51.100.8"}); err != nil {
		t.Fatal(err)
	}
}

// Review Focus 1: only the latest code is valid; the first counts as an
// attempt.
func TestStartReplacesPreviousCode(t *testing.T) {
	e := newTestEnv(t)
	first := e.emailCode("ada@example.test")
	second := e.emailCode("ada@example.test")
	for first == second {
		second = e.emailCode("ada@example.test")
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", first); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("first code = %v", err)
	}
	row, _ := e.st.Phone().ConsumePasswordlessCode(e.ctx, tid, "con_email", "ada@example.test", "code", "wrong", 3, testNow)
	if row != nil {
		t.Fatal("consumed with wrong hash")
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", second); err != nil {
		t.Fatalf("latest code = %v", err)
	}
	// Used codes fail.
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", second); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed code = %v", err)
	}
	// A link replaces an outstanding code too.
	code := e.emailCode("ada@example.test")
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test", Send: "link"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code after link = %v", err)
	}
}

func TestCodeAttemptsAndExpiry(t *testing.T) {
	e := newTestEnv(t)
	code := e.emailCode("ada@example.test")
	for i := 0; i < 3; i++ {
		if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", "000000"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("wrong %d = %v", i, err)
		}
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code after 3 wrong attempts = %v", err)
	}
	code = e.emailCode("ada@example.test")
	e.advance(181 * time.Second)
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expired code = %v", err)
	}
	// A code issued to another client is refused.
	code = e.emailCode("ada@example.test")
	if _, err := e.svc.VerifyCode(e.ctx, tid, "other", "email", "ada@example.test", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("other client = %v", err)
	}
}

func TestConcurrentVerifyOneWins(t *testing.T) {
	e := newTestEnv(t)
	code := e.smsCode("+14155550123")
	var wins, fails atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "sms", "+14155550123", code); err == nil {
				wins.Add(1)
			} else if errors.Is(err, ErrInvalidCode) {
				fails.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || fails.Load() != 7 {
		t.Fatalf("wins=%d fails=%d", wins.Load(), fails.Load())
	}
	users, _ := e.st.Phone().FindUsersByPhone(e.ctx, tid, "sms", "+14155550123")
	if len(users) != 1 {
		t.Fatalf("users = %d", len(users))
	}
}

func linkToken(t *testing.T, m email.PasswordlessEmail) string {
	t.Helper()
	u, err := url.Parse(m.Link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("verification_code")
}

// Review Focus 2: a scanner's peek never burns the link.
func TestLinkScannerDoesNotConsume(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test", AuthParams: url.Values{"scope": {"openid offline_access"}}}); err != nil {
		t.Fatal(err)
	}
	token := linkToken(t, e.mail.last(t))
	for i := 0; i < 3; i++ {
		if _, _, err := e.svc.PeekLink(e.ctx, tid, token); err != nil {
			t.Fatalf("peek %d: %v", i, err)
		}
	}
	g, err := e.svc.VerifyLink(e.ctx, tid, token)
	if err != nil {
		t.Fatal(err)
	}
	if g.User == nil || g.User.Email != "ada@example.test" || !g.User.EmailVerified || g.ClientID != "cli" || g.Connection.Name != "email" {
		t.Fatalf("grant = %+v", g)
	}
	// Magic links never return refresh tokens.
	if strings.Contains(g.AuthParams.Get("scope"), "offline_access") || g.AuthParams.Get("scope") != "openid" {
		t.Fatalf("scope = %q", g.AuthParams.Get("scope"))
	}
}

func TestLinkReuseFails(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test"}); err != nil {
		t.Fatal(err)
	}
	token := linkToken(t, e.mail.last(t))
	if _, err := e.svc.VerifyLink(e.ctx, tid, token); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyLink(e.ctx, tid, token); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("reuse = %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tid, token); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("peek after use = %v", err)
	}
	// A newer link replaces an older one; expired links fail.
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test"}); err != nil {
		t.Fatal(err)
	}
	old := linkToken(t, e.mail.last(t))
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test"}); err != nil {
		t.Fatal(err)
	}
	latest := linkToken(t, e.mail.last(t))
	if _, err := e.svc.VerifyLink(e.ctx, tid, old); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replaced link = %v", err)
	}
	e.advance(181 * time.Second)
	if _, err := e.svc.VerifyLink(e.ctx, tid, latest); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expired link = %v", err)
	}
}

func TestConcurrentLinkOneWins(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test"}); err != nil {
		t.Fatal(err)
	}
	token := linkToken(t, e.mail.last(t))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.VerifyLink(e.ctx, tid, token); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins = %d", wins.Load())
	}
}

func TestBruteForceBlocksIdentifier(t *testing.T) {
	e := newTestEnv(t)
	tn, _ := e.st.Tenants().Get(e.ctx, tid)
	tn.ProtectionSettings.BruteForce.MaxAttempts = 4
	if err := e.st.Tenants().Update(e.ctx, tn); err != nil {
		t.Fatal(err)
	}
	// Each code allows 3 attempts; the identifier block spans codes.
	for i := 0; i < 4; i++ {
		if i%3 == 0 {
			e.emailCode("ada@example.test")
		}
		if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", "000000"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("wrong %d = %v", i, err)
		}
	}
	code := e.emailCode("ada@example.test")
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("blocked identifier = %v", err)
	}
	if len(e.rec.of("limit_wc")) == 0 {
		t.Fatal("limit_wc not logged")
	}
	// Without brute_force_protection on the connection the code works.
	conn, _ := e.st.Connections().GetByName(e.ctx, tid, "email")
	conn.BruteForceProtection = false
	if err := e.st.Connections().Update(e.ctx, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); err != nil {
		t.Fatalf("unprotected connection = %v", err)
	}
}

func TestVerifyDisableSignupAndBlocked(t *testing.T) {
	e := newTestEnv(t)
	code := e.emailCode("new@example.test")
	conn, _ := e.st.Connections().GetByName(e.ctx, tid, "email")
	conn.DisableSignup = true
	if err := e.st.Connections().Update(e.ctx, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "new@example.test", code); !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("disable_signup = %v", err)
	}
	if len(e.rec.of("fu")) != 1 {
		t.Fatal("fu not logged")
	}
	conn.DisableSignup = false
	if err := e.st.Connections().Update(e.ctx, conn); err != nil {
		t.Fatal(err)
	}
	u, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "new@example.test", e.emailCode("new@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	code = e.emailCode("new@example.test")
	u.Blocked = true
	if err := e.st.Users().Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "new@example.test", code); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("blocked = %v", err)
	}
}

func TestPhoneUnavailable(t *testing.T) {
	e := newTestEnv(t)
	e.svc.Store = noPhone{e.st}
	_, err := e.start(StartInput{Connection: "email", Email: "ada@example.test", Send: "code"})
	if !errors.Is(err, store.ErrPhoneUnavailable) {
		t.Fatalf("start = %v", err)
	}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", "123456"); !errors.Is(err, store.ErrPhoneUnavailable) {
		t.Fatalf("verify = %v", err)
	}
}

type noPhone struct{ *memory.Store }

func (noPhone) Phone() store.Phone { return store.UnimplementedPhone{} }

// hookStore runs after on the skip+1th FindByLogin (the protection lookup
// comes first), between the user lookup and the verified-flag write.
type hookStore struct {
	*memory.Store
	skip  int
	after func()
}

func (h *hookStore) Users() store.Users { return hookUsers{h.Store.Users(), h} }

type hookUsers struct {
	store.Users
	h *hookStore
}

func (u hookUsers) FindByLogin(ctx context.Context, tid, conn, login string) (*store.User, error) {
	got, err := u.Users.FindByLogin(ctx, tid, conn, login)
	if u.h.skip > 0 {
		u.h.skip--
		return got, err
	}
	if f := u.h.after; f != nil && err == nil {
		u.h.after = nil
		f()
	}
	return got, err
}

func (e *testEnv) putUser(u *store.User) {
	e.t.Helper()
	u.TenantID = tid
	if err := e.st.Users().Create(e.ctx, u); err != nil {
		e.t.Fatal(err)
	}
}

// Review fix 1: a block (or any admin edit) landing between the lookup and
// the verified-flag write is never undone.
func TestVerifyDoesNotUndoConcurrentBlock(t *testing.T) {
	e := newTestEnv(t)
	e.putUser(&store.User{UserID: "email|aaaaaaaaaaaaaaaaaaaaaaaa", Email: "ada@example.test", Identities: []store.Identity{{Connection: "email", Provider: "email", UserID: "aaaaaaaaaaaaaaaaaaaaaaaa"}}})
	code := e.emailCode("ada@example.test")
	e.svc.Store = &hookStore{Store: e.st, skip: 1, after: func() {
		u, _ := e.st.Users().Get(e.ctx, tid, "email|aaaaaaaaaaaaaaaaaaaaaaaa")
		u.Blocked, u.AppMetadata = true, map[string]any{"plan": "gold"}
		if err := e.st.Users().Update(e.ctx, u); err != nil {
			t.Error(err)
		}
	}}
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("verify = %v", err)
	}
	u, _ := e.st.Users().Get(e.ctx, tid, "email|aaaaaaaaaaaaaaaaaaaaaaaa")
	if !u.Blocked || u.AppMetadata["plan"] != "gold" {
		t.Fatalf("concurrent edit undone: %+v", u)
	}
}

// Review fix 2: signing in through a linked identity's email never marks the
// primary user's (different) email verified.
func TestVerifyLinkedIdentityKeepsPrimaryUnverified(t *testing.T) {
	e := newTestEnv(t)
	e.putUser(&store.User{UserID: "auth0|primary", Email: "primary@example.test", Identities: []store.Identity{
		{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: "primary"},
		{Connection: "email", Provider: "email", UserID: "bbbbbbbbbbbbbbbbbbbbbbbb", ProfileData: map[string]any{"email": "linked@example.test", "email_verified": false}},
	}})
	res, err := e.start(StartInput{Connection: "email", Email: "linked@example.test", Send: "code"})
	if err != nil || res.Verified {
		t.Fatalf("start = %+v %v", res, err)
	}
	u, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "linked@example.test", e.mail.last(t).Code)
	if err != nil || u.UserID != "auth0|primary" {
		t.Fatalf("verify = %+v %v", u, err)
	}
	if got, _ := e.st.Users().Get(e.ctx, tid, "auth0|primary"); got.EmailVerified {
		t.Fatal("primary email marked verified by a linked identity's code")
	}
	// The primary identity's own address is marked verified.
	e.putUser(&store.User{UserID: "email|cccccccccccccccccccccccc", Email: "own@example.test", Identities: []store.Identity{{Connection: "email", Provider: "email", UserID: "cccccccccccccccccccccccc"}}})
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "own@example.test", e.emailCode("own@example.test")); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.Users().Get(e.ctx, tid, "email|cccccccccccccccccccccccc"); !got.EmailVerified {
		t.Fatal("own email not marked verified")
	}
	if res, _ := e.start(StartInput{Connection: "email", Email: "own@example.test", Send: "code"}); !res.Verified {
		t.Fatal("start Verified false for a verified primary email")
	}
}

// Review fix 4: magic-link sign-ins obey the Plan 19 brute-force block.
func TestLinkObeysBruteForceBlock(t *testing.T) {
	e := newTestEnv(t)
	tn, _ := e.st.Tenants().Get(e.ctx, tid)
	tn.ProtectionSettings.BruteForce.MaxAttempts = 2
	if err := e.st.Tenants().Update(e.ctx, tn); err != nil {
		t.Fatal(err)
	}
	e.emailCode("ada@example.test")
	for range 2 {
		if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", "000000"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("wrong = %v", err)
		}
	}
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test"}); err != nil {
		t.Fatal(err)
	}
	token := linkToken(t, e.mail.last(t))
	if _, err := e.svc.VerifyLink(e.ctx, tid, token); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("blocked link sign-in = %v", err)
	}
	// The refused attempt did not burn the link.
	if _, _, err := e.svc.PeekLink(e.ctx, tid, token); err != nil {
		t.Fatalf("link burned by a refused sign-in: %v", err)
	}
}

// Review fix 3: parallel wrong guesses are each counted, so the right code
// is refused once three wrong guesses landed.
func TestConcurrentWrongGuessesExhaustCode(t *testing.T) {
	e := newTestEnv(t)
	conn, _ := e.st.Connections().GetByName(e.ctx, tid, "email")
	conn.BruteForceProtection = false
	if err := e.st.Connections().Update(e.ctx, conn); err != nil {
		t.Fatal(err)
	}
	code := e.emailCode("ada@example.test")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", wrong)
		}()
	}
	wg.Wait()
	if _, err := e.svc.VerifyCode(e.ctx, tid, "cli", "email", "ada@example.test", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code after 12 parallel wrong guesses = %v", err)
	}
}
