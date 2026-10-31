package mgmt_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type managementEvents struct{ events []logs.Event }

func (c *managementEvents) Record(ctx context.Context, e logs.Event) {
	// The boundary is checked with the real recorder scrub policy too.
	e.Details = logscrub.ScrubValueContext(ctx, e.Details).(map[string]any)
	c.events = append(c.events, e)
}
func logSetup(e *clientsEnv) *managementEvents {
	c := &managementEvents{}
	e.h.Recorder = c
	e.h.Log = slog.New(slog.DiscardHandler)
	return c
}
func onlyEvent(t *testing.T, c *managementEvents, typ string) logs.Event {
	t.Helper()
	if len(c.events) != 1 || c.events[0].Type != typ {
		t.Fatalf("events=%+v, want one %s", c.events, typ)
	}
	return c.events[0]
}
func eventJSON(t *testing.T, e logs.Event) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestManagementWriteLogged(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	w, out := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", map[string]any{"name": "Created"}, http.HandlerFunc(e.h.CreateClient))
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	ev := onlyEvent(t, c, "sapi")
	if ev.ClientID != "m2m" || ev.TenantID != e.tn.ID {
		t.Fatalf("actor %+v", ev)
	}
	raw := eventJSON(t, ev)
	secret := out.(map[string]any)["client_secret"].(string)
	if strings.Contains(raw, secret) || !strings.Contains(raw, logscrub.Marker) {
		t.Fatalf("unsafe event %s", raw)
	}
}
func TestManagementFailedWriteLogged(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	w, _ := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", `{"unknown":true}`, http.HandlerFunc(e.h.CreateClient))
	if w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	onlyEvent(t, c, "fapi")
}
func TestManagementReadNotLogged(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	w, _ := e.call(t, e.tn, m2mCaller("read:clients"), "GET", "/api/v2/clients", nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.GetClients(w, r, mgmtapi.GetClientsParams{}) }))
	if w.Code != 200 || len(c.events) != 0 {
		t.Fatalf("%d events %+v", w.Code, c.events)
	}
}
func TestManagementSecretReadLogged(t *testing.T) {
	e := newClientsEnv(t)
	client := e.mustCreate(t, map[string]any{"name": "Read"})
	c := logSetup(e)
	w, out := e.call(t, e.tn, m2mCaller("read:clients", "read:client_keys"), "GET", "/api/v2/clients/"+client["client_id"].(string), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.h.GetClient(w, r, client["client_id"].(string), mgmtapi.GetClientParams{})
	}))
	if w.Code != 200 || out.(map[string]any)["client_secret"] != client["client_secret"] {
		t.Fatalf("response changed: %d %s", w.Code, w.Body)
	}
	ev := onlyEvent(t, c, "mgmt_api_read")
	if strings.Contains(eventJSON(t, ev), client["client_secret"].(string)) {
		t.Fatal("secret in read event")
	}
}
func TestManagementBodyPasswordHidden(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/v2/users", `{"password":"hunter2!","name":"hunter2!","user_metadata":{"five":{"nested":{"password":"hunter2!"}}}}`},
		{"PATCH", "/api/v2/users/auth0|u", `{"password":"a","name":"a","app_metadata":"{\"password\":\"a\"}"}`},
		{"POST", "/api/v2/jobs/users-imports", "--multipart\r\npassword_hash:hunter2!\r\n"},
		{"POST", "/api/v2/emails/provider", `{"name":"smtp","credentials":{"smtp_pass":"hunter2!"},"enabled":true}`},
		{"PATCH", "/api/v2/log-streams/lst_1", `{"name":"stream","sink":{"httpEndpoint":"https://user:hunter2!@example.com","httpAuthorization":"hunter2!"}}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			e := newClientsEnv(t)
			c := logSetup(e)
			e.call(t, e.tn, m2mCaller(), tc.method, tc.path, tc.body, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				w.WriteHeader(400)
				w.Write(b)
			}))
			raw := eventJSON(t, onlyEvent(t, c, "fapi"))
			if strings.Contains(raw, "hunter2!") || strings.Contains(raw, `\"name\":\"a\"`) || !strings.Contains(raw, logscrub.Marker) {
				t.Fatalf("unsafe event: %s", raw)
			}
		})
	}
}
func TestManagementCapturePreservesBodies(t *testing.T) {
	for _, size := range []int{0, 65535, 65536, 65537, 1048577} {
		t.Run(string(rune(size)), func(t *testing.T) {
			e := newClientsEnv(t)
			c := logSetup(e)
			body := strings.Repeat("x", size)
			w, _ := e.call(t, e.tn, m2mCaller(), "POST", "/api/v2/clients", body, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != int64(size) {
					t.Fatalf("ContentLength=%d", r.ContentLength)
				}
				b, err := io.ReadAll(r.Body)
				if err != nil || string(b) != body {
					t.Fatalf("body len=%d err=%v", len(b), err)
				}
				w.WriteHeader(201)
				w.Write(b)
			}))
			if w.Body.String() != body {
				t.Fatal("response changed")
			}
			ev := onlyEvent(t, c, "sapi")
			if size > 65536 && ev.Details["response"].(map[string]any)["body"] != logscrub.Marker {
				t.Fatal("partial body logged")
			}
		})
	}
}
func TestManagementCaptureAllowlistNested(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	body := `{"branding":{"logo_url":"https://example.com/logo","colors":{"primary":"blue","password":"secret"},"unknown":{"name":"hidden"}},"unknown":{"name":"hidden"}}`
	e.call(t, e.tn, m2mCaller(), "PATCH", "/api/v2/organizations/org_1?per_page=10&bearer=hidden", body, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	ev := onlyEvent(t, c, "sapi")
	req := ev.Details["request"].(map[string]any)
	b := req["body"].(map[string]any)
	branding := b["branding"].(map[string]any)
	if branding["logo_url"] != "https://example.com/logo" || branding["unknown"] != logscrub.Marker || b["unknown"] != logscrub.Marker {
		t.Fatalf("allowlist %+v", b)
	}
	if strings.Contains(eventJSON(t, ev), "hidden") {
		t.Fatal("unknown/query leaked")
	}
}
func TestManagementOperatorAndUnauthenticatedPolicy(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	e.call(t, e.tn, mgmt.Caller{Kind: mgmt.Operator, ClientID: "console", UserID: "auth0|operator"}, "DELETE", "/api/v2/clients/target", nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	if ev := onlyEvent(t, c, "sapi"); ev.UserID != "auth0|operator" {
		t.Fatalf("actor %+v", ev)
	}
	c.events = nil
	req := httptest.NewRequest("POST", "/api/v2/clients", nil)
	req = req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: &store.Tenant{ID: e.tn.ID}}))
	w := httptest.NewRecorder()
	mgmt.Auth(mgmt.Config{Store: e.st})(e.h.LogMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated handler called") }))).ServeHTTP(w, req)
	if w.Code != 401 || len(c.events) != 0 {
		t.Fatalf("%d %+v", w.Code, c.events)
	}
}

var captureReadError = errors.New("body read failed")

type failingManagementBody struct {
	read   bool
	closed bool
}

func (b *failingManagementBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(p, "partial"), captureReadError
}
func (b *failingManagementBody) Close() error { b.closed = true; return nil }
func TestManagementCapturePreservesReadErrorAndClose(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	b := &failingManagementBody{}
	req := httptest.NewRequest("POST", "/api/v2/clients", nil)
	req.Body = b
	req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn}), m2mCaller()))
	e.h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if string(got) != "partial" || !errors.Is(err, captureReadError) {
			t.Fatalf("%q %v", got, err)
		}
		r.Body.Close()
		w.WriteHeader(400)
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !b.closed {
		t.Fatal("original body not closed")
	}
	onlyEvent(t, c, "fapi")
}
func TestManagementCaptureResponseStreaming(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v2/clients", bytes.NewBufferString(`{}`))
	req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn}), m2mCaller()))
	e.h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(103)
		w.WriteHeader(201)
		w.Write([]byte(`{"name":`))
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("Flusher lost")
		}
		f.Flush()
		io.Copy(w, strings.NewReader(`"streamed"}`))
	})).ServeHTTP(w, req)
	ev := onlyEvent(t, c, "sapi")
	if ev.Details["response"].(map[string]any)["statusCode"] != 201 || w.Body.String() != `{"name":"streamed"}` || !w.Flushed {
		t.Fatalf("response %+v %s", ev, w.Body)
	}
}

func assertManagementTypes(t *testing.T, c *managementEvents, want ...string) {
	t.Helper()
	got := map[string]int{}
	for _, e := range c.events {
		got[e.Type]++
	}
	if len(c.events) != len(want) {
		t.Fatalf("event counts=%v want=%v", got, want)
	}
	for _, typ := range want {
		if got[typ] != 1 {
			t.Fatalf("event counts=%v want=%v", got, want)
		}
	}
}
func TestManagementUserDomainLogged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"email", map[string]any{"email": "new@example.test"}, 200, "sce"},
		{"password", map[string]any{"password": "different horse 2"}, 200, "scp"},
		{"password refused", map[string]any{"password": "x"}, 400, "fcp"},
		{"username refused", map[string]any{"username": "changed"}, 400, "fcu"},
		{"email refused", map[string]any{"email": "invalid"}, 400, "fce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newUsersEnv(t)
			id := e.mustCreate(t, map[string]any{"email": "old@example.test"})["user_id"].(string)
			c := logSetup(e.clientsEnv)
			w, _ := e.call(t, e.tn, m2mCaller(allUserScopes...), "PATCH", "/api/v2/users/"+id, tc.body, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) }))
			if w.Code != tc.status {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			api := "sapi"
			if tc.status >= 400 {
				api = "fapi"
			}
			assertManagementTypes(t, c, tc.code, api)
			for _, ev := range c.events {
				if ev.Type == tc.code && (ev.UserID != id || ev.ConnectionID != e.conn.ID || ev.TenantID != e.tn.ID) {
					t.Fatalf("attribution %+v", ev)
				}
			}
		})
	}
}
func TestManagementUserNoopAndDeleteLogged(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "old@example.test"})["user_id"].(string)
	c := logSetup(e.clientsEnv)
	e.call(t, e.tn, m2mCaller(allUserScopes...), "PATCH", "/api/v2/users/"+id, map[string]any{"email": "old@example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) }))
	assertManagementTypes(t, c, "sapi")
	c.events = nil
	e.call(t, e.tn, m2mCaller(allUserScopes...), "DELETE", "/api/v2/users/"+id, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUser(w, r, id) }))
	assertManagementTypes(t, c, "sdu", "sapi")
	c.events = nil
	e.call(t, e.tn, m2mCaller(allUserScopes...), "DELETE", "/api/v2/users/"+id, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUser(w, r, id) }))
	assertManagementTypes(t, c, "sapi")
}
func TestManagementVerificationDomainLogged(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "verify@example.test"})["user_id"].(string)
	c := logSetup(e.clientsEnv)
	for _, tc := range []struct{ id, code, api string }{{id, "svr", "sapi"}, {"auth0|missing", "fvr", "fapi"}} {
		c.events = nil
		e.call(t, e.tn, m2mCaller(), "POST", "/api/v2/jobs/verification-email", map[string]any{"user_id": tc.id}, http.HandlerFunc(e.h.CreateVerificationEmailJob))
		assertManagementTypes(t, c, tc.code, tc.api)
	}
}
func TestManagementMembershipDomainLogged(t *testing.T) {
	e, id := newMemberEnv(t)
	c := logSetup(e.clientsEnv)
	for i := 0; i < 2; i++ {
		c.events = nil
		w, _ := e.call(t, e.tn, e.caller, "POST", "/api/v2/organizations/"+id+"/members", map[string]any{"members": []string{memberUser(1)}}, e.members(id))
		if w.Code != 204 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if i == 0 {
			assertManagementTypes(t, c, "organization_member_added", "sapi")
			if c.events[0].UserID != memberUser(1) || c.events[0].OrganizationID != id {
				t.Fatalf("attribution %+v", c.events[0])
			}
		} else {
			assertManagementTypes(t, c, "sapi")
		}
	}
}

func TestManagementUnblockDomainLogged(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "blocked@example.test"})["user_id"].(string)
	e.h.Now = func() time.Time { return now }
	c := logSetup(e.clientsEnv)
	key := protection.LoginKey(e.tn.ID, e.conn.ID, "blocked@example.test", "192.0.2.3", "count_per_identifier_and_ip")
	a, err := e.st.Protection().Reserve(context.Background(), []store.ProtectionLimit{{Key: key, Algorithm: "brute-force", Capacity: 1, Window: time.Hour, Lockout: time.Hour, Refill: time.Hour}}, now)
	if err != nil || !a.Allowed {
		t.Fatalf("%+v %v", a, err)
	}
	if err := e.st.Protection().Complete(context.Background(), a.Receipt, "failure", now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.events = nil
		w, _ := e.call(t, e.tn, m2mCaller(), "DELETE", "/api/v2/user-blocks/"+id, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UserBlocks(w, r, id) }))
		if w.Code != 204 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if i == 0 {
			assertManagementTypes(t, c, "ublkdu", "sapi")
		} else {
			assertManagementTypes(t, c, "sapi")
		}
	}
}

type managementDNS struct{ err error }

func (d managementDNS) LookupTXT(context.Context, string) ([]string, error) { return nil, d.err }
func (d managementDNS) LookupCNAME(context.Context, string) (string, error) { return "", d.err }
func (d managementDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, d.err
}
func TestManagementDomainVerificationLogged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dnsErr error
		want   []string
	}{{"missing proof", customdomain.ErrDNSNotFound, []string{"custom_domain_verification_failed", "sapi"}}, {"unavailable proof", errors.New("resolver unavailable"), []string{"sapi"}}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newClientsEnv(t)
			c := logSetup(e)
			e.h.Domains = customdomain.NewService(e.st, managementDNS{tc.dnsErr}, customdomain.ServiceConfig{OriginDomain: "origin.example.test", ManagedEnabled: true}, func() time.Time { return now }, rand.Reader)
			d, err := e.h.Domains.Create(context.Background(), e.tn.ID, customdomain.CreateInput{Domain: "login.verified.example", Type: customdomain.TypeManaged})
			if err != nil {
				t.Fatal(err)
			}
			w, _ := e.call(t, e.tn, m2mCaller(), "POST", "/api/v2/custom-domains/"+d.ID+"/verify", nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.VerifyCustomDomain(w, r, d.ID) }))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			assertManagementTypes(t, c, tc.want...)
		})
	}
}
func TestManagementBreachDomainLogged(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "breach@example.test"})["user_id"].(string)
	tn, err := e.st.Tenants().Get(context.Background(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	tn.ProtectionSettings = protectionrules.Defaults()
	tn.ProtectionSettingsInitialized = true
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Stage.PreChangePassword.Shields = []string{"block"}
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	e.h.Protection = &protection.Service{Store: e.st, BreachChecker: breachStub{}}
	c := logSetup(e.clientsEnv)
	e.call(t, e.tn, m2mCaller(allUserScopes...), "PATCH", "/api/v2/users/"+id, map[string]any{"password": "breached horse 2"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) }))
	assertManagementTypes(t, c, "reset_pwd_leak", "fcp", "fapi")
}

// Interface presence and return values must survive capture for streaming and
// ResponseController users, even on transports with uncommon method sets.
type managementPushWriter struct {
	*httptest.ResponseRecorder
	pushed bool
}

func (w *managementPushWriter) Push(string, *http.PushOptions) error {
	w.pushed = true
	return http.ErrNotSupported
}

type managementReaderWriter struct {
	http.ResponseWriter
	readFrom bool
}

func (w *managementReaderWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(w.ResponseWriter, r)
}
func TestManagementCaptureOptionalInterfaces(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	r := httptest.NewRequest("POST", "/api/v2/clients", strings.NewReader(`{}`))
	r = r.WithContext(mgmt.WithCaller(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: e.tn}), m2mCaller()))
	push := &managementPushWriter{ResponseRecorder: httptest.NewRecorder()}
	e.h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := w.(http.Pusher)
		if !ok {
			t.Fatal("Pusher lost")
		}
		if err := p.Push("/asset", nil); !errors.Is(err, http.ErrNotSupported) {
			t.Fatal(err)
		}
		w.WriteHeader(201)
	})).ServeHTTP(push, r)
	if !push.pushed {
		t.Fatal("Push not forwarded")
	}
	onlyEvent(t, c, "sapi")
	c.events = nil
	rf := &managementReaderWriter{ResponseWriter: httptest.NewRecorder()}
	e.h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(io.ReaderFrom)
		if !ok {
			t.Fatal("ReaderFrom lost")
		}
		n, err := f.ReadFrom(strings.NewReader(`{"name":"copied"}`))
		if err != nil || n != 17 {
			t.Fatalf("%d %v", n, err)
		}
	})).ServeHTTP(rf, r)
	ev := onlyEvent(t, c, "sapi")
	if ev.Details["response"].(map[string]any)["body"].(map[string]any)["name"] != "copied" {
		t.Fatal("ReadFrom bypassed capture")
	}
}
func TestManagementStreamCredentialsMaskCopies(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	raw := `{"sink":{"httpEndpoint":"https://user:private@example.test"},"name":"https://user:private@example.test"}`
	e.call(t, e.tn, m2mCaller(), "POST", "/api/v2/log-streams", raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	if strings.Contains(eventJSON(t, onlyEvent(t, c, "sapi")), "private") {
		t.Fatal("sink secret copy leaked")
	}
}
func TestManagementSystemWriteExcluded(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	e.call(t, e.tn, mgmt.Caller{Kind: mgmt.Operator, UserID: "op"}, "PATCH", "/api/system/tenants/acme", `{}`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	if len(c.events) != 0 {
		t.Fatal("system operation became tenant Management event")
	}
}

func TestManagementSecretReadExcludesMetadataAndRedactedValues(t *testing.T) {
	for _, tc := range []struct{ path, body string }{{"/api/v2/clients/one", `{"client_metadata":{"client_secret":"metadata"},"client_secret":"[REDACTED]"}`}, {"/api/v2/users/auth0|one", `{"user_metadata":{"access_token":"metadata"},"identities":[{"access_token":"[REDACTED]"}]}`}, {"/api/v2/actions/actions/one", `{"secrets":[{"name":"KEY","updated_at":"now"}]}`}} {
		t.Run(tc.path, func(t *testing.T) {
			e := newClientsEnv(t)
			c := logSetup(e)
			e.call(t, e.tn, m2mCaller(), "GET", tc.path, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) }))
			if len(c.events) != 0 {
				t.Fatalf("redacted-only or metadata read emitted %+v", c.events)
			}
		})
	}
}
func TestManagementSecretReadBeyondCaptureLogged(t *testing.T) {
	e := newClientsEnv(t)
	client := e.mustCreate(t, map[string]any{"name": "Large"})
	id := client["client_id"].(string)
	saved, err := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	saved.Callbacks = []string{"https://example.com/" + strings.Repeat("x", 70000)}
	if err := e.st.Clients().Update(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	c := logSetup(e)
	w, _ := e.call(t, e.tn, m2mCaller("read:clients", "read:client_keys"), "GET", "/api/v2/clients/"+id, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.GetClient(w, r, id, mgmtapi.GetClientParams{}) }))
	if w.Code != 200 || !strings.Contains(w.Body.String(), client["client_secret"].(string)) {
		t.Fatal("large public read changed")
	}
	ev := onlyEvent(t, c, "mgmt_api_read")
	if ev.Details["response"].(map[string]any)["body"] != logscrub.Marker {
		t.Fatal("large body not hidden")
	}
}

func TestManagementStrictParserPreserved(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	for _, tc := range []struct{ name, body, message string }{
		{"trailing JSON", `{"name":"ok"} {}`, "Payload validation error: the body must be a JSON object"},
		{"array", `[]`, "Payload validation error: the body must be a JSON object"},
		{"null", `null`, "Payload validation error: the body must be a JSON object"},
		{"malformed JSON", `{"name":`, "Payload validation error: the body must be a JSON object"},
		{"over 1 MiB", strings.Repeat(" ", 1048577), "Payload validation error: the body is too large or unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "https://login.acme.test/api/v2/clients?include_fields=true", strings.NewReader(tc.body))
				ctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "login.acme.test"})
				return req.WithContext(mgmt.WithCaller(ctx, m2mCaller(allClientScopes...)))
			}
			// The baseline deliberately bypasses clientsEnv.call, which installs the
			// middleware itself. Each branch owns a fresh body and identical context.
			plain := httptest.NewRecorder()
			e.h.CreateClient(plain, request())
			logged := httptest.NewRecorder()
			e.h.LogMiddleware(http.HandlerFunc(e.h.CreateClient)).ServeHTTP(logged, request())
			for _, response := range []struct {
				name   string
				writer *httptest.ResponseRecorder
			}{{"bare", plain}, {"middleware", logged}} {
				var body struct {
					StatusCode int    `json:"statusCode"`
					ErrorCode  string `json:"errorCode"`
					Message    string `json:"message"`
				}
				if err := json.Unmarshal(response.writer.Body.Bytes(), &body); err != nil {
					t.Fatalf("%s invalid error JSON: %v", response.name, err)
				}
				if response.writer.Code != http.StatusBadRequest || body.StatusCode != 400 || body.ErrorCode != "invalid_body" || body.Message != tc.message {
					t.Errorf("%s: status=%d body status=%d code=%q message=%q; want 400/400 invalid_body %q", response.name, response.writer.Code, body.StatusCode, body.ErrorCode, body.Message, tc.message)
				}
			}
			if logged.Code != plain.Code || logged.Body.String() != plain.Body.String() {
				t.Error("middleware changed the bare handler's strict-parser response")
			}
		})
	}
}
func TestManagementLargeBodyRegistersCredentialsBeforeScripts(t *testing.T) {
	e := newUsersEnv(t)
	conn, executor := e.legacy(t, "legacy-large", false, map[string]func([]any) (any, error){})
	const secret = "large-body-password"
	executor.Funcs[store.ScriptGetUser] = func([]any) (any, error) { return nil, &customdb.ScriptError{Message: secret, Kind: customdb.KindError} }
	output := &bytes.Buffer{}
	e.h.Log = slog.New(slog.NewTextHandler(output, nil))
	c := &managementEvents{}
	e.h.Recorder = c
	body := map[string]any{"connection": conn.Name, "email": "large@example.test", "password": secret, "user_metadata": map[string]any{"padding": strings.Repeat("x", 70000)}}
	e.call(t, e.tn, m2mCaller(allUserScopes...), "POST", "/api/v2/users", body, http.HandlerFunc(e.h.CreateUser))
	if strings.Contains(output.String(), secret) {
		t.Fatalf("script error leaked: %s", output)
	}
	if strings.Contains(eventJSON(t, onlyEvent(t, c, "fapi")), secret) {
		t.Fatal("event leaked password")
	}
}

func TestManagementUsernameDomainLogged(t *testing.T) {
	e := newUsersEnv(t)
	e.conn.RequiresUsername = true
	if err := e.st.Connections().Update(context.Background(), e.conn); err != nil {
		t.Fatal(err)
	}
	id := e.mustCreate(t, map[string]any{"email": "username@example.test", "username": "before"})["user_id"].(string)
	c := logSetup(e.clientsEnv)
	w, _ := e.call(t, e.tn, m2mCaller(allUserScopes...), "PATCH", "/api/v2/users/"+id, map[string]any{"username": "after"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) }))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	assertManagementTypes(t, c, "scu", "sapi")
}
func TestManagementDeleteFailureDomainLogged(t *testing.T) {
	e := newUsersEnv(t)
	conn, _ := e.legacy(t, "legacy-delete", false, map[string]func([]any) (any, error){store.ScriptDelete: func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "refused"}
	}})
	id := e.legacyUser(t, conn, "deleteme", "delete@example.test")
	c := logSetup(e.clientsEnv)
	w, _ := e.call(t, e.tn, m2mCaller(allUserScopes...), "DELETE", "/api/v2/users/"+id, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUser(w, r, id) }))
	if w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	assertManagementTypes(t, c, "fdu", "fapi")
	if c.events[0].UserID != id || c.events[0].ConnectionID != conn.ID {
		t.Fatalf("attribution %+v", c.events[0])
	}
}
func TestManagementRateLimitLogged(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	e.call(t, e.tn, m2mCaller(), "POST", "/api/v2/clients", `{}`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
	assertManagementTypes(t, c, "api_limit", "fapi")
}
func TestManagementOperatorLiveGrantBeforeLogging(t *testing.T) {
	e := newEnv(t)
	events := &managementEvents{}
	h := &mgmt.Handlers{Recorder: events, Log: slog.New(slog.DiscardHandler)}
	auth := mgmt.Auth(mgmt.Config{Store: e.st, Keys: e.km, BaseDomain: base, SystemHost: systemHost, Now: func() time.Time { return now }})
	handler := tenant.NewResolver(e.st.Tenants(), base, false).Middleware(auth(h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))))
	raw := e.mint(t, operator("https://"+systemHost+"/", []string{"*"}))
	call := func() int {
		r := httptest.NewRequest("DELETE", "https://acme.example.com/api/v2/clients/one", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if status := call(); status != 204 {
		t.Fatal(status)
	}
	if onlyEvent(t, events, "sapi").UserID != "auth0|op" {
		t.Fatal("operator actor missing")
	}
	events.events = nil
	op, err := e.st.Operators().Get(context.Background(), e.ids["system"], "auth0|op")
	if err != nil {
		t.Fatal(err)
	}
	op.Tenants = []string{"globex"}
	if err := e.st.Operators().Upsert(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if status := call(); status != 403 || len(events.events) != 0 {
		t.Fatalf("revoked grant status=%d events=%+v", status, events.events)
	}
}

func TestManagementCredentialURLsHidden(t *testing.T) {
	e := newClientsEnv(t)
	c := logSetup(e)
	body := `{"callbacks":["https://user:url-password@example.com/callback","https://example.com/cb?access_token=url-token"],"name":"url-password"}`
	e.call(t, e.tn, m2mCaller(), "PATCH", "/api/v2/clients/one", body, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	raw := eventJSON(t, onlyEvent(t, c, "sapi"))
	if strings.Contains(raw, "url-password") || strings.Contains(raw, "url-token") {
		t.Fatalf("URL credential leaked %s", raw)
	}
}

type managementFlushErrorWriter struct{ *httptest.ResponseRecorder }

func (w *managementFlushErrorWriter) FlushError() error { return captureReadError }
func TestManagementCaptureControllerFlushError(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	r := httptest.NewRequest("POST", "/api/v2/clients", nil)
	r = r.WithContext(mgmt.WithCaller(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: e.tn}), m2mCaller()))
	e.h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); !errors.Is(err, captureReadError) {
			t.Fatalf("flush error changed: %v", err)
		}
	})).ServeHTTP(&managementFlushErrorWriter{httptest.NewRecorder()}, r)
}
