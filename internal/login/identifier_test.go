package login

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var hostedRevisionField = regexp.MustCompile(`name="hosted_revision" value="([0-9]+)"`)

func revisionFrom(t *testing.T, body string) string {
	t.Helper()
	m := hostedRevisionField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("missing hosted revision: %s", body)
	}
	return m[1]
}
func enableIdentifier(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	tn, err := e.st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.st.HostedLogins().Get(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Prompts = map[string]any{"identifier_first": true}
	if err := e.st.HostedLogins().Put(ctx, c, c.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifierFirstFlow(t *testing.T) {
	e := newEnv(t)
	enableIdentifier(t, e)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	if strings.Contains(page.Body.String(), `id="password"`) {
		t.Fatal("identifier page contains password")
	}
	revision := revisionFrom(t, page.Body.String())
	step := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revision}, "username": {"alice@acme.test"}})
	if step.Code != http.StatusSeeOther || !strings.HasPrefix(step.Header().Get("Location"), "/u/login/password?") {
		t.Fatalf("identifier=%d %s", step.Code, step.Body.String())
	}
	password := b.do(t, "GET", step.Header().Get("Location"), nil)
	if password.Code != http.StatusOK || !strings.Contains(password.Body.String(), "alice@acme.test") {
		t.Fatalf("password=%d %s", password.Code, password.Body.String())
	}
	done := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, password.Body.String())}, "password": {"alice password 1"}, "username": {"carol@acme.test"}})
	if done.Code != http.StatusFound || !strings.Contains(done.Header().Get("Location"), "code=") {
		t.Fatalf("password submit=%d %s %s", done.Code, done.Header().Get("Location"), done.Body.String())
	}
	replay := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {"1"}, "password": {"alice password 1"}})
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay=%d", replay.Code)
	}
}

func TestIdentifierFirstNoLookup(t *testing.T) {
	for _, identifier := range []string{"alice@acme.test", "nobody@acme.test"} {
		t.Run(identifier, func(t *testing.T) {
			e := newEnv(t)
			enableIdentifier(t, e)
			b := e.browser("acme.example.test")
			page, state, csrf := b.begin(t)
			response := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {identifier}})
			if response.Code != http.StatusSeeOther {
				t.Fatalf("identifier status=%d", response.Code)
			}
		})
	}
}

func TestIdentifierFirstDirectPasswordDenied(t *testing.T) {
	e := newEnv(t)
	enableIdentifier(t, e)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	response := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"alice password 1"}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("direct password=%d", response.Code)
	}
}

func TestIdentifierFirstRetryResetAndSettingChange(t *testing.T) {
	e := newEnv(t)
	enableIdentifier(t, e)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	tn := mustTenant(t, e, "acme")
	before, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {"alice@acme.test"}})
	password := b.do(t, "GET", "/u/login/password?state="+state, nil)
	oldRevision := revisionFrom(t, password.Body.String())
	// An in-flight transaction keeps its captured flow when the setting changes.
	c, err := e.st.HostedLogins().Get(context.Background(), tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Prompts["identifier_first"] = false
	if err := e.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
		t.Fatal(err)
	}
	wrong := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {oldRevision}, "password": {"wrong"}})
	if wrong.Code != http.StatusUnauthorized || !strings.Contains(wrong.Body.String(), `action="/u/login/password"`) {
		t.Fatalf("wrong password=%d %s", wrong.Code, wrong.Body.String())
	}
	if revisionFrom(t, wrong.Body.String()) == oldRevision {
		t.Fatal("denial did not rotate revision")
	}
	stale := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {oldRevision}, "password": {"alice password 1"}})
	if stale.Code != http.StatusBadRequest {
		t.Fatalf("stale=%d", stale.Code)
	}
	reset := b.do(t, "POST", "/u/login/identifier", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, wrong.Body.String())}})
	if reset.Code != http.StatusSeeOther {
		t.Fatalf("reset=%d", reset.Code)
	}
	after, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if after.HostedState.Step != "identifier" || after.HostedState.Identifier != "" || !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("reset changed lifetime or retained identity: %+v", after)
	}
	combined, _, _ := e.browser("acme.example.test").begin(t)
	if !strings.Contains(combined.Body.String(), `id="password"`) {
		t.Fatal("new transaction ignored disabled setting")
	}
}

func TestIdentifierFirstConcurrentPassword(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "shared.db")
	first, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	e := newEnvWithStore(t, first)
	enableIdentifier(t, e)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseScript := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseScript)
	var calls atomic.Int32
	e.scripts.Funcs[store.ScriptLogin] = func(args []any) (any, error) {
		if calls.Add(1) == 1 {
			close(reached)
			<-release
		}
		return legacyLogin(args)
	}
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t, "client_id", "legacy", "redirect_uri", "https://legacy.acme.test/cb")
	step := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {"dave@legacy.test"}})
	if step.Code != http.StatusSeeOther || calls.Load() != 0 {
		t.Fatalf("identifier called database: status=%d calls=%d", step.Code, calls.Load())
	}
	password := b.do(t, "GET", step.Header().Get("Location"), nil)
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, password.Body.String())}, "password": {"dave legacy 1"}}
	other := *e.h
	other.Store = second
	database := *e.h.Database
	database.Store = second
	other.Database = &database
	e2 := *e
	e2.h = &other
	e2.srv = tenant.NewResolver(second.Tenants(), "", false).Middleware(http.HandlerFunc(other.LoginPasswordPost))
	b2 := e2.browser("acme.example.test")
	for k, v := range b.cookies {
		copy := *v
		b2.cookies[k] = &copy
	}
	done := make(chan int, 1)
	go func() { done <- b.send("POST", "/u/login/password", form).Code }()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("authentication not reached")
	}
	denied := b2.do(t, "POST", "/u/login/password", form)
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("second password=%d %s", denied.Code, denied.Body.String())
	}
	releaseScript()
	select {
	case status := <-done:
		if status != http.StatusFound {
			t.Fatalf("first password=%d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first authentication stuck")
	}
	if calls.Load() != 1 {
		t.Fatalf("authentication calls=%d", calls.Load())
	}
}

func TestIdentifierFirstBindingsAndCrash(t *testing.T) {
	e := newEnv(t)
	enableIdentifier(t, e)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {"alice@acme.test"}})
	password := b.do(t, "GET", "/u/login/password?state="+state, nil)
	revision := revisionFrom(t, password.Body.String())
	for _, form := range []url.Values{
		{"state": {state}, "csrf": {"wrong"}, "hosted_revision": {revision}},
		{"state": {state}, "csrf": {csrf}, "hosted_revision": {revision, revision}},
	} {
		if response := b.do(t, "POST", "/u/login/identifier", form); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid reset accepted: %d", response.Code)
		}
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revision}, "password": {"alice password 1"}}
	if response := e.browser("acme.example.test").do(t, "POST", "/u/login/password", form); response.Code != http.StatusBadRequest {
		t.Fatalf("wrong cookie accepted: %d", response.Code)
	}
	tn := mustTenant(t, e, "acme")
	txn, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	next := txn.HostedState.Clone()
	next.Step = "authenticating"
	if err := e.st.AuthTransactions().CompareAndSwapHosted(context.Background(), tn.ID, state, txn.HostedState.Revision, next, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if response := b.do(t, "GET", "/u/login/password?state="+state, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("crashed authentication reopened: %d", response.Code)
	}
	if response := b.do(t, "POST", "/u/login/password", form); response.Code != http.StatusBadRequest {
		t.Fatalf("crashed authentication replayed: %d", response.Code)
	}
	e.h.Now = func() time.Time { return txn.ExpiresAt }
	if response := b.do(t, "GET", "/u/login?state="+state, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("expired flow=%d", response.Code)
	}
}
