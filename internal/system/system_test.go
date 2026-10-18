package system_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func wrapper(t *testing.T) keys.Wrapper {
	t.Helper()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestEnsureCreatesSystemTenant(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	cfg := system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}
	tn, err := system.Ensure(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tn.Name != tenant.SystemName || !tn.Reserved || tn.Seeded || !slices.Equal(tn.Domains, []string{"admin.example.test"}) {
		t.Fatalf("tenant = %+v", tn)
	}
	if tn.DefaultDirectory != system.OperatorsConnection {
		t.Errorf("default directory = %q", tn.DefaultDirectory)
	}
	c, err := st.Clients().Get(ctx, tn.ID, system.ConsoleClientID)
	if err != nil {
		t.Fatal(err)
	}
	if c.AppType != store.AppTypeSPA || c.TokenEndpointAuthMethod != store.AuthMethodNone || !c.IsFirstParty ||
		!slices.Equal(c.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
		!slices.Equal(c.Callbacks, []string{"https://admin.example.test/admin/callback"}) ||
		!slices.Equal(c.AllowedLogoutURLs, []string{"https://admin.example.test/admin/"}) ||
		!slices.Equal(c.WebOrigins, []string{"https://admin.example.test"}) ||
		!c.RefreshToken.Rotating || !c.RefreshToken.Expiring || len(c.Secrets) != 0 {
		t.Errorf("console client = %+v", c)
	}
	conn, err := st.Connections().GetByName(ctx, tn.ID, system.OperatorsConnection)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Strategy != store.StrategyDatabase || !conn.DisableSignup || !slices.Equal(conn.EnabledClients, []string{system.ConsoleClientID}) {
		t.Errorf("connection = %+v", conn)
	}
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, system.ManagementAudience)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.AllowOfflineAccess || rs.SubjectTypeAuthorization.Client != store.PolicyDenyAll {
		t.Errorf("resource server = %+v", rs)
	}
	ks, err := st.SigningKeys().List(ctx, tn.ID)
	if err != nil || len(ks) != 2 {
		t.Errorf("signing keys = %d, %v", len(ks), err)
	}
	r := tenant.NewResolver(st.Tenants(), "", false)
	if got, err := r.Resolve(ctx, "Admin.Example.TEST:443"); err != nil || got.Tenant.ID != tn.ID {
		t.Errorf("resolve system host = %+v, %v", got, err)
	}
}

func TestEnsureIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	cfg := system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}
	first, err := system.Ensure(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys1, _ := st.SigningKeys().List(ctx, first.ID)
	conn1, _ := st.Connections().GetByName(ctx, first.ID, system.OperatorsConnection)
	second, err := system.Ensure(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys2, _ := st.SigningKeys().List(ctx, first.ID)
	conn2, _ := st.Connections().GetByName(ctx, first.ID, system.OperatorsConnection)
	tenants, _ := st.Tenants().List(ctx)
	if second.ID != first.ID || len(tenants) != 1 || len(keys2) != len(keys1) || keys2[0].KID != keys1[0].KID || conn2.ID != conn1.ID {
		t.Fatalf("second Ensure changed things: %+v %+v", first, second)
	}

	// A new system host replaces the old one.
	moved, err := system.Ensure(ctx, st, system.Config{Host: "console.example.test", Wrapper: wrapper(t)})
	if err != nil || !slices.Equal(moved.Domains, []string{"console.example.test"}) {
		t.Fatalf("moved = %+v, %v", moved, err)
	}
	c, _ := st.Clients().Get(ctx, first.ID, system.ConsoleClientID)
	if !slices.Equal(c.Callbacks, []string{"https://console.example.test/admin/callback"}) {
		t.Errorf("callbacks = %v", c.Callbacks)
	}
}

func TestEnsureRefusals(t *testing.T) {
	ctx := context.Background()
	if _, err := system.Ensure(ctx, memory.New(), system.Config{Wrapper: wrapper(t)}); err == nil {
		t.Error("an empty host was accepted")
	}
	// Another tenant holding the host.
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"admin.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := system.Ensure(ctx, st, system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("host clash: %v", err)
	}
	// A tenant named system that zeroauthy did not create.
	st = memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_s", Name: "system"}); err != nil {
		t.Fatal(err)
	}
	if _, err := system.Ensure(ctx, st, system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}); err == nil || !strings.Contains(err.Error(), "not zeroauthy's") {
		t.Errorf("foreign system tenant: %v", err)
	}
}

type discardMailer struct{}

func (discardMailer) Send(context.Context, email.Message) error { return nil }

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

const (
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// The setup link sets the operator's password through the hosted reset
// page, and the operator then signs in to the console client.
func TestCreateOperatorLinkWorks(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := wrapper(t)
	km := keys.NewManager(st.SigningKeys(), w)
	srv := httptest.NewTLSServer(server.New(server.Deps{
		Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions:     &session.Manager{Store: st},
		Mailer:       discardMailer{},
		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	base := "https://" + host
	tn, err := system.Ensure(ctx, st, system.Config{Host: host, Wrapper: w})
	if err != nil {
		t.Fatal(err)
	}

	link, err := system.CreateOperator(ctx, st, " Admin@Example.TEST ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, base+"/u/reset-password?ticket=") {
		t.Fatalf("link = %q", link)
	}
	u, err := st.Users().FindByLogin(ctx, tn.ID, system.OperatorsConnection, "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	op, err := st.Operators().Get(ctx, tn.ID, u.UserID)
	if err != nil || !slices.Equal(op.Tenants, []string{store.OperatorAllTenants}) {
		t.Fatalf("operator = %+v, %v", op, err)
	}
	lu, _ := url.Parse(link)
	tk, err := st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(lu.Query().Get("ticket")))
	if err != nil || tk.ExpiresAt.Sub(tk.CreatedAt) != time.Hour {
		t.Fatalf("ticket = %+v, %v", tk, err)
	}

	jar, _ := cookiejar.New(nil)
	c := srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(u string) (*http.Response, string) {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	post := func(u string, form url.Values) (*http.Response, string) {
		t.Helper()
		resp, err := c.PostForm(u, form)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	// 1. Set the password through the link.
	resp, page := get(link)
	csrf := csrfRe.FindStringSubmatch(page)
	if resp.StatusCode != 200 || csrf == nil {
		t.Fatalf("reset page = %d %s", resp.StatusCode, page)
	}
	const pw = "operator password 1"
	resp, page = post(base+"/u/reset-password", url.Values{"ticket": {lu.Query().Get("ticket")}, "csrf": {csrf[1]}, "password": {pw}, "password_confirm": {pw}})
	if resp.StatusCode != 200 {
		t.Fatalf("reset submit = %d %s", resp.StatusCode, page)
	}

	// 2. Sign in to the console.
	q := url.Values{"client_id": {system.ConsoleClientID}, "redirect_uri": {base + "/admin/callback"}, "response_type": {"code"},
		"scope": {"openid offline_access"}, "audience": {system.ManagementAudience}, "state": {"s1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	resp, _ = get(base + "/authorize?" + q.Encode())
	loginURL, _ := resp.Location()
	if resp.StatusCode != 302 || loginURL == nil || loginURL.Path != "/u/login" {
		t.Fatalf("authorize = %d %v", resp.StatusCode, loginURL)
	}
	_, page = get(base + loginURL.RequestURI())
	csrf = csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf on login page: %s", page)
	}
	resp, page = post(base+"/u/login", url.Values{"state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"admin@example.test"}, "password": {pw}})
	cb, _ := resp.Location()
	if resp.StatusCode != 302 || cb == nil || cb.Path != "/admin/callback" || cb.Query().Get("code") == "" {
		t.Fatalf("login = %d %v %s", resp.StatusCode, cb, page)
	}
	resp, page = post(base+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {system.ConsoleClientID},
		"code": {cb.Query().Get("code")}, "redirect_uri": {base + "/admin/callback"}, "code_verifier": {verifier}})
	if resp.StatusCode != 200 || !strings.Contains(page, "access_token") || !strings.Contains(page, "refresh_token") {
		t.Fatalf("token = %d %s", resp.StatusCode, page)
	}
}

func TestCreateOperatorErrors(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if _, err := system.CreateOperator(ctx, st, "a@example.test"); err == nil {
		t.Error("CreateOperator without a system tenant succeeded")
	}
	if _, err := system.Ensure(ctx, st, system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CreateOperator(ctx, st, "not an address"); err == nil {
		t.Error("a bad address was accepted")
	}
	// Running it again for the same address issues a new link for the same user.
	l1, err := system.CreateOperator(ctx, st, "a@example.test")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := system.CreateOperator(ctx, st, "a@example.test")
	if err != nil || l1 == l2 {
		t.Fatalf("second invite = %q, %v", l2, err)
	}
	tn, _ := st.Tenants().GetByName(ctx, tenant.SystemName)
	ops, _ := st.Operators().List(ctx, tn.ID)
	if len(ops) != 1 {
		t.Fatalf("operators = %d", len(ops))
	}
}

func TestBootstrapOnce(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if _, err := system.Ensure(ctx, st, system.Config{Host: "admin.example.test", Wrapper: wrapper(t)}); err != nil {
		t.Fatal(err)
	}
	link, err := system.Bootstrap(ctx, st, "first@example.test")
	if err != nil || link == "" {
		t.Fatalf("first bootstrap = %q, %v", link, err)
	}
	link, err = system.Bootstrap(ctx, st, "first@example.test")
	if err != nil || link != "" {
		t.Fatalf("second bootstrap = %q, %v", link, err)
	}
	link, err = system.Bootstrap(ctx, st, "other@example.test")
	if err != nil || link != "" {
		t.Fatalf("bootstrap with an operator present = %q, %v", link, err)
	}
	if link, err := system.Bootstrap(ctx, st, ""); err != nil || link != "" {
		t.Fatalf("empty email = %q, %v", link, err)
	}
}

// dropReserved mimics a storage plugin that predates Tenant.reserved.
type dropReserved struct{ store.Store }
type dropReservedTenants struct{ store.Tenants }

func (d dropReserved) Tenants() store.Tenants { return dropReservedTenants{d.Store.Tenants()} }
func (d dropReserved) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return d.Store.WithTx(ctx, func(tx store.Store) error { return fn(dropReserved{tx}) })
}
func (t dropReservedTenants) Create(ctx context.Context, tn *store.Tenant) error {
	c := *tn
	c.Reserved = false
	return t.Tenants.Create(ctx, &c)
}

func TestEnsureNeedsReservedFlag(t *testing.T) {
	_, err := system.Ensure(context.Background(), dropReserved{memory.New()}, system.Config{Host: "admin.example.test", Wrapper: wrapper(t)})
	if err == nil || !strings.Contains(err.Error(), "must be upgraded") {
		t.Fatalf("err = %v", err)
	}
}
