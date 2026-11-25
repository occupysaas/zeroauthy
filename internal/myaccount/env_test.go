package myaccount

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const host = "login.acme.test"

var allScopes = []string{"read:me:factors", "read:me:authentication_methods", "create:me:authentication_methods", "update:me:authentication_methods", "delete:me:authentication_methods"}

type env struct {
	st    store.Store
	w     keys.Wrapper
	km    *keys.Manager
	tn    *store.Tenant
	conn  *store.Connection
	user  *store.User
	h     *Handlers
	now   time.Time
	logs  *bytes.Buffer
	route http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tn, err := tenantsetup.UpsertTenant(ctx, st, "acme", now, func(t *store.Tenant) error {
		t.Domains, t.CanonicalHost = []string{host}, host
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tenantsetup.MyAccountAPI(ctx, st, tn, now); err != nil {
		t.Fatal(err)
	}
	if err := tenantsetup.UpsertConnection(ctx, st, tn.ID, "Username-Password-Authentication", now, func(c *store.Connection) error {
		c.Strategy = store.StrategyDatabase
		c.EnabledClients = []string{"app"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	conn, _ := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	u := newUser(t, st, tn.ID, "auth0|alice1", "alice@acme.test", now)
	logs := &bytes.Buffer{}
	e := &env{st: st, w: w, km: km, tn: tn, conn: conn, user: u, now: now, logs: logs}
	e.h = &Handlers{Store: st, Keys: km, Wrapper: w, Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.MultiWriter(logs), nil))}
	e.route = e.h.Routes()
	return e
}

func newUser(t *testing.T, st store.Store, tid, uid, email string, now time.Time) *store.User {
	t.Helper()
	id := strings.TrimPrefix(uid, "auth0|")
	u := &store.User{TenantID: tid, UserID: uid, Email: email, EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: "Username-Password-Authentication", Provider: store.StrategyDatabase, UserID: id, PasswordHash: "$argon2id$v=19$m=65536,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"}}}
	if err := st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Users().Get(context.Background(), tid, uid)
	return got
}

// tokenFor signs a My Account access token for uid with scopes.
func (e *env) tokenFor(t *testing.T, uid string, scopes ...string) string {
	t.Helper()
	if len(scopes) == 0 {
		scopes = allScopes
	}
	raw, err := e.km.SignWithType(context.Background(), e.tn.ID, map[string]any{
		"iss": "https://" + host + "/", "aud": []string{"https://" + host + "/me/", "https://" + host + "/userinfo"}, "sub": uid, "azp": "app",
		"scope": strings.Join(scopes, " "), "iat": e.now.Unix(), "exp": e.now.Add(time.Hour).Unix(), "jti": "j1",
	}, "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *env) token(t *testing.T, scopes ...string) string {
	return e.tokenFor(t, e.user.UserID, scopes...)
}

// do serves one request for path (relative to /me/v1) on the tenant host.
func (e *env) do(t *testing.T, tok, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://"+host+Path+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: e.tn, Host: host}))
	rec := httptest.NewRecorder()
	http.StripPrefix(Path, e.route).ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// addAuthenticator stores a confirmed method for uid.
func (e *env) addAuthenticator(t *testing.T, a store.Authenticator) store.Authenticator {
	t.Helper()
	a.TenantID = e.tn.ID
	if a.UserID == "" {
		a.UserID = e.user.UserID
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = e.now
	}
	a.LastStep = -1
	var err error
	if a.Type == "passkey" {
		err = e.st.WebAuthn().CreatePasskey(context.Background(), &a, 20)
	} else {
		err = e.st.MFA().CreateAuthenticator(context.Background(), &a)
	}
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) guardian(t *testing.T, factors ...string) {
	t.Helper()
	ctx := context.Background()
	g, err := e.st.MFA().GetGuardian(ctx, e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.Factors == nil {
		g.Factors = map[string]bool{}
	}
	for _, f := range factors {
		g.Factors[f] = true
	}
	if err := e.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
}
