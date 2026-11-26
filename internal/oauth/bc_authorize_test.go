package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const cibaGrant = "urn:openid:params:grant-type:ciba"

type fakeApprovalMail struct {
	mu   sync.Mutex
	sent []email.AsyncApprovalEmail
	wg   sync.WaitGroup
}

func (m *fakeApprovalMail) SendAsyncApproval(_ context.Context, e email.AsyncApprovalEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	return nil
}

type cibaFixture struct {
	*fixture
	mail  *fakeApprovalMail
	tid   string
	alice *store.User
}

// newCIBAFixture adds ciba-app (the CIBA grant, email channel) and bob, a
// user without a verified email.
func newCIBAFixture(t *testing.T) *cibaFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	sealed, err := keys.SealClientSecret(f.wrapper, tid, "ciba-app", "ciba-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Clients().Create(ctx, &store.Client{TenantID: tid, ClientID: "ciba-app", Name: "Agent backend", AppType: store.AppTypeRegularWeb, IsFirstParty: true,
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, Secrets: []store.ClientSecret{{Sealed: sealed, CreatedAt: fixedNow()}},
		GrantTypes: []string{"authorization_code", cibaGrant}, AsyncApprovalNotificationChannels: []string{"email"}, CreatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Users().Create(ctx, &store.User{TenantID: tid, UserID: "auth0|bob", Email: "bob@acme.test", EmailVerified: false, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
	found, err := f.st.Users().FindByEmail(ctx, tid, "alice@acme.test")
	if err != nil || len(found) == 0 {
		t.Fatalf("alice: %v", err)
	}
	alice := found[0]
	mail := &fakeApprovalMail{}
	f.h.CIBA = NewCIBAService(mail, fixedNow)
	f.h.CIBA.sent = mail.wg.Done
	return &cibaFixture{fixture: f, mail: mail, tid: tid, alice: alice}
}

func cibaHint(sub string) string {
	return `{"format":"iss_sub","iss":"https://acme.example.test/","sub":"` + sub + `"}`
}

func (f *cibaFixture) bcForm(sub string, kv ...string) url.Values {
	v := url.Values{"client_id": {"ciba-app"}, "client_secret": {"ciba-secret"}, "scope": {"openid email"}, "login_hint": {cibaHint(sub)},
		"binding_message": {"ORDER-42"}, "requested_expiry": {"600"}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			v.Del(kv[i])
		} else {
			v.Set(kv[i], kv[i+1])
		}
	}
	return v
}

func (f *cibaFixture) bcAuthorize(t *testing.T, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := contract.Wrap(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.BcAuthorize)))
	r := httptest.NewRequest(http.MethodPost, "https://acme.example.test/bc-authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestBCAuthorizeAccepts(t *testing.T) {
	f := newCIBAFixture(t)
	f.mail.wg.Add(1)
	rec, out := f.bcAuthorize(t, f.bcForm(f.alice.UserID))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || out["expires_in"] != float64(600) || out["interval"] != float64(5) {
		t.Fatalf("answer %d %v", rec.Code, out)
	}
	id := out["auth_req_id"].(string)
	f.mail.wg.Wait()
	r, err := f.st.(store.CIBAStore).GetCIBARequest(context.Background(), f.tid, secrets.HashToken(id))
	if err != nil || r.UserID != f.alice.UserID || r.ClientID != "ciba-app" || r.BindingMessage != "ORDER-42" || r.Status != store.CIBAPending ||
		!r.ExpiresAt.Equal(fixedNow().Add(600*time.Second)) || r.Origin != "https://acme.example.test" {
		t.Fatalf("stored %+v %v", r, err)
	}
	if len(f.mail.sent) != 1 {
		t.Fatalf("mails %d", len(f.mail.sent))
	}
	m := f.mail.sent[0]
	u, _ := url.Parse(m.URL)
	if m.User.UserID != f.alice.UserID || m.BindingMessage != "ORDER-42" || u.Scheme != "https" || u.Host != "acme.example.test" || u.Path != "/bc-verify" ||
		r.TicketHash != secrets.HashToken(u.Query().Get("consent")) || strings.Contains(m.URL, id) {
		t.Fatalf("mail %+v", m)
	}
}

func TestBCAuthorizeRefusals(t *testing.T) {
	f := newCIBAFixture(t)
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"wrong secret":    {f.bcForm(f.alice.UserID, "client_secret", "nope"), 401, "invalid_client"},
		"no grant":        {url.Values{"client_id": {"web"}, "client_secret": {"web-secret"}, "scope": {"openid"}, "login_hint": {cibaHint("x")}, "binding_message": {"A"}, "requested_expiry": {"600"}}, 403, "unauthorized_client"},
		"no openid":       {f.bcForm(f.alice.UserID, "scope", "email"), 400, "invalid_scope"},
		"push window":     {f.bcForm(f.alice.UserID, "requested_expiry", "120"), 400, "invalid_request"},
		"bad binding":     {f.bcForm(f.alice.UserID, "binding_message", "hello world"), 400, "invalid_request"},
		"unknown API":     {f.bcForm(f.alice.UserID, "audience", "https://nope.test/"), 400, "invalid_request"},
		"unsigned object": {f.bcForm(f.alice.UserID, "request", "eyJhbGciOiJub25lIn0.e30."), 400, "invalid_request_object"},
	}
	for name, tc := range cases {
		rec, out := f.bcAuthorize(t, tc.form)
		if rec.Code != tc.status || out["error"] != tc.code {
			t.Errorf("%s: %d %v", name, rec.Code, out)
		}
	}
	// A client whose channels lost email is refused at request time.
	c, _ := f.st.Clients().Get(context.Background(), f.tid, "ciba-app")
	c.AsyncApprovalNotificationChannels = []string{"guardian-push"}
	_ = f.st.Clients().Update(context.Background(), c)
	if rec, out := f.bcAuthorize(t, f.bcForm(f.alice.UserID)); rec.Code != 400 || out["error"] != "invalid_request" {
		t.Fatalf("push only: %d %v", rec.Code, out)
	}
	if len(f.mail.sent) != 0 {
		t.Fatalf("refusals sent %d mails", len(f.mail.sent))
	}
}

// Review Focus 1: an unknown user, a user without a verified email and a
// valid user get identical answers, in comparable time.
func TestBCAuthorizeNoOracle(t *testing.T) {
	f := newCIBAFixture(t)
	f.h.CIBA = NewCIBAService(f.mail, nil) // a real clock: many requests
	f.h.CIBA.sent = f.mail.wg.Done
	shape := func(rec *httptest.ResponseRecorder, out map[string]any) string {
		keys := []string{}
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		hdr := []string{}
		for k := range rec.Header() {
			hdr = append(hdr, k)
		}
		sort.Strings(hdr)
		id, _ := out["auth_req_id"].(string)
		return strings.Join([]string{http.StatusText(rec.Code), strings.Join(keys, ","), strings.Join(hdr, ","), rec.Header().Get("Cache-Control"),
			jsonNum(out["expires_in"]), jsonNum(out["interval"]), strings.Repeat("x", len(id))}, "|")
	}
	subjects := map[string]string{"valid": f.alice.UserID, "unknown": "auth0|nobody", "unverified": "auth0|bob"}
	shapes := map[string]string{}
	times := map[string][]time.Duration{}
	for round := range 5 {
		for name, sub := range subjects {
			if name == "valid" {
				f.mail.wg.Add(1)
			}
			start := time.Now()
			rec, out := f.bcAuthorize(t, f.bcForm(sub, "binding_message", "R"+string(rune('0'+round))))
			times[name] = append(times[name], time.Since(start))
			s := shape(rec, out)
			if prev, ok := shapes[name]; ok && prev != s {
				t.Fatalf("%s answers vary: %s vs %s", name, prev, s)
			}
			shapes[name] = s
		}
	}
	f.mail.wg.Wait()
	if shapes["valid"] != shapes["unknown"] || shapes["valid"] != shapes["unverified"] {
		t.Fatalf("answers differ:\n%v", shapes)
	}
	median := func(d []time.Duration) time.Duration {
		s := slices.Clone(d)
		slices.Sort(s)
		return s[len(s)/2]
	}
	v, u := median(times["valid"]), median(times["unknown"])
	if diff := v - u; diff > 20*time.Millisecond || -diff > 20*time.Millisecond {
		t.Fatalf("timing differs: valid %v, unknown %v", v, u)
	}
	if len(f.mail.sent) != 5 {
		t.Fatalf("mails %d, want 5 (valid user only)", len(f.mail.sent))
	}
	for _, m := range f.mail.sent {
		if m.User.UserID != f.alice.UserID {
			t.Fatalf("mail to %s", m.User.UserID)
		}
	}
}

func jsonNum(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestBCAuthorizeLimits(t *testing.T) {
	f := newCIBAFixture(t)
	for i := range 5 {
		f.mail.wg.Add(1)
		if rec, out := f.bcAuthorize(t, f.bcForm(f.alice.UserID)); rec.Code != 200 {
			t.Fatalf("request %d: %d %v", i, rec.Code, out)
		}
	}
	f.mail.wg.Wait()
	if rec, out := f.bcAuthorize(t, f.bcForm(f.alice.UserID)); rec.Code != http.StatusTooManyRequests || out["error"] != "too_many_requests" {
		t.Fatalf("sixth for one user: %d %v", rec.Code, out)
	}
	// The pending limit: 5000 per tenant.
	repo := f.st.(store.CIBAStore)
	for i := range 5000 {
		_ = repo.CreateCIBARequest(context.Background(), &store.CIBARequest{TenantID: f.tid, IDHash: "fill" + itoa(i), TicketHash: "tfill" + itoa(i), ClientID: "ciba-app",
			Status: store.CIBAPending, Interval: 5, ExpiresAt: fixedNow().Add(time.Hour), CreatedAt: fixedNow()})
	}
	if rec, out := f.bcAuthorize(t, f.bcForm("auth0|someone-else")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("pending limit: %d %v", rec.Code, out)
	}
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + jsonNum(i)) }

// A signed request object carries the parameters (JAR, Plan 35).
func TestBCAuthorizeRequestObject(t *testing.T) {
	f := newCIBAFixture(t)
	f.useJAR(t, "ciba-app", false)
	claims := assertionClaims("ciba-app", "sub", nil, "client_id", "ciba-app", "scope", "openid", "login_hint", cibaHint(f.alice.UserID),
		"binding_message", "SIGNED-1", "requested_expiry", "900")
	obj := signAssertion(t, pkjwtKey(t, "rsa2048.priv.pem"), jose.RS256, "", claims)
	f.mail.wg.Add(1)
	rec, out := f.bcAuthorize(t, url.Values{"client_id": {"ciba-app"}, "client_secret": {"ciba-secret"}, "request": {obj}})
	if rec.Code != 200 || out["expires_in"] != float64(900) {
		t.Fatalf("signed request: %d %v", rec.Code, out)
	}
	f.mail.wg.Wait()
	if f.mail.sent[0].BindingMessage != "SIGNED-1" {
		t.Fatalf("binding message from the object: %+v", f.mail.sent[0])
	}
}
