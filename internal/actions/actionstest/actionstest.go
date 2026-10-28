// Package actionstest runs real Action flows in tests of the packages that
// call the engine: a memory or other store, an empty built dependency set
// per tenant and the Node runner.
package actionstest

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// RequireNode skips without a usable Node.js (22.13+), or fails under
// ZA_REQUIRE_NODE=1.
func RequireNode(t testing.TB) {
	t.Helper()
	reason := ""
	if p, err := exec.LookPath("node"); err != nil {
		reason = "node not found on PATH"
	} else if out, err := exec.Command(p, "--version").Output(); err != nil {
		reason = "node --version failed: " + err.Error()
	} else if err := noderunner.CheckNodeVersion(strings.TrimSpace(string(out))); err != nil {
		reason = err.Error()
	}
	if reason == "" {
		return
	}
	if os.Getenv("ZA_REQUIRE_NODE") == "1" {
		t.Fatalf("ZA_REQUIRE_NODE=1 but %s", reason)
	}
	t.Skip(reason)
}

// Logs is a log sink safe for the runner's stderr goroutines.
type Logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Env is an Actions engine over a store.
type Env struct {
	Engine *actions.Engine
	Store  store.Store
	Logs   *Logs
	builds *build.Manager
	built  map[string]string
}

// New returns an engine over st whose secrets open with w.
func New(t testing.TB, st store.Store, w keys.Wrapper) *Env {
	t.Helper()
	RequireNode(t)
	logs := &Logs{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := config.Actions{CacheDir: t.TempDir(), IdleTimeout: time.Minute}
	builds, err := build.New(cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(builds.Close)
	pool, err := actions.NewRunner(cfg, builds, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return &Env{Engine: &actions.Engine{Store: st, Runner: pool, Builds: builds, Secrets: w, Log: log},
		Store: st, Logs: logs, builds: builds, built: map[string]string{}}
}

// emptyBuild returns the tenant's built empty dependency set.
func (e *Env) emptyBuild(t testing.TB, tenantID string) string {
	t.Helper()
	if id, ok := e.built[tenantID]; ok {
		return id
	}
	ctx := context.Background()
	id, err := e.builds.Queue(ctx, tenantID, nil, actionsrules.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		b, err := e.Store.Actions().GetBuild(ctx, tenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		if b.Status == store.BuildBuilt {
			break
		}
		if b.Status == store.BuildFailed || time.Now().After(deadline) {
			t.Fatalf("empty build: %+v", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.built[tenantID] = id
	return id
}

// Deploy creates and deploys an Action named name with code.
func (e *Env) Deploy(t testing.TB, tenantID, trigger, name, code string) *store.Action {
	t.Helper()
	ctx := context.Background()
	a := &store.Action{TenantID: tenantID, ID: "act_" + name, Name: name, Trigger: trigger, Runtime: actionsrules.Runtime,
		Code: code, DraftBuildID: e.emptyBuild(t, tenantID)}
	if err := e.Store.Actions().CreateAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.Actions().Deploy(ctx, tenantID, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	return a
}

// Bind replaces the trigger's bindings with as, in order.
func (e *Env) Bind(t testing.TB, tenantID, trigger string, as ...*store.Action) {
	t.Helper()
	b := []store.Binding{}
	for _, a := range as {
		b = append(b, store.Binding{ActionID: a.ID, DisplayName: a.Name})
	}
	if _, err := e.Store.Actions().ReplaceBindings(context.Background(), tenantID, trigger, b); err != nil {
		t.Fatal(err)
	}
}

// PostLogin deploys code as the tenant's only post-login Action.
func (e *Env) PostLogin(t testing.TB, tenantID, name, code string) {
	t.Helper()
	e.Bind(t, tenantID, actions.TriggerPostLogin, e.Deploy(t, tenantID, actions.TriggerPostLogin, name, code))
}

// CredentialsExchange deploys code as the tenant's only
// credentials-exchange Action.
func (e *Env) CredentialsExchange(t testing.TB, tenantID, name, code string) {
	t.Helper()
	e.Bind(t, tenantID, actions.TriggerCredentialsExchange, e.Deploy(t, tenantID, actions.TriggerCredentialsExchange, name, code))
}

// Counts counts repository use through a CountingStore: each accessor
// call (one per query in practice) by repository name, and the Actions
// repository's Bindings and CreateExecution calls ("Actions.Bindings",
// "Actions.CreateExecution").
type Counts struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *Counts) add(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[name]++
}

// Snapshot returns a copy of the counts.
func (c *Counts) Snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for k, v := range c.n {
		out[k] = v
	}
	return out
}

// Reset clears the counts.
func (c *Counts) Reset() {
	c.mu.Lock()
	c.n = nil
	c.mu.Unlock()
}

// CountingStore wraps a store and counts its repository use in Counts,
// transactions included.
type CountingStore struct {
	store.Store
	Counts *Counts
}

func (s CountingStore) WithTx(ctx context.Context, fn func(tx store.Store) error) error {
	s.Counts.add("WithTx")
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(CountingStore{tx, s.Counts}) })
}

func (s CountingStore) Actions() store.Actions {
	s.Counts.add("Actions")
	return countingActions{s.Store.Actions(), s.Counts}
}

type countingActions struct {
	store.Actions
	c *Counts
}

func (a countingActions) Bindings(ctx context.Context, tenantID, trigger string) ([]store.BoundVersion, error) {
	a.c.add("Actions.Bindings")
	return a.Actions.Bindings(ctx, tenantID, trigger)
}

func (a countingActions) CreateExecution(ctx context.Context, e *store.Execution) error {
	a.c.add("Actions.CreateExecution")
	return a.Actions.CreateExecution(ctx, e)
}

func (s CountingStore) RBAC() store.RBAC       { s.Counts.add("RBAC"); return s.Store.RBAC() }
func (s CountingStore) Tenants() store.Tenants { s.Counts.add("Tenants"); return s.Store.Tenants() }
func (s CountingStore) Clients() store.Clients { s.Counts.add("Clients"); return s.Store.Clients() }
func (s CountingStore) ResourceServers() store.ResourceServers {
	s.Counts.add("ResourceServers")
	return s.Store.ResourceServers()
}
func (s CountingStore) ClientGrants() store.ClientGrants {
	s.Counts.add("ClientGrants")
	return s.Store.ClientGrants()
}
func (s CountingStore) UserGrants() store.UserGrants {
	s.Counts.add("UserGrants")
	return s.Store.UserGrants()
}
func (s CountingStore) SigningKeys() store.SigningKeys {
	s.Counts.add("SigningKeys")
	return s.Store.SigningKeys()
}
func (s CountingStore) Connections() store.Connections {
	s.Counts.add("Connections")
	return s.Store.Connections()
}
func (s CountingStore) Users() store.Users       { s.Counts.add("Users"); return s.Store.Users() }
func (s CountingStore) Sessions() store.Sessions { s.Counts.add("Sessions"); return s.Store.Sessions() }
func (s CountingStore) AuthTransactions() store.AuthTransactions {
	s.Counts.add("AuthTransactions")
	return s.Store.AuthTransactions()
}
func (s CountingStore) AuthCodes() store.AuthCodes {
	s.Counts.add("AuthCodes")
	return s.Store.AuthCodes()
}
func (s CountingStore) DeviceCodes() store.DeviceCodes {
	s.Counts.add("DeviceCodes")
	return s.Store.DeviceCodes()
}
func (s CountingStore) RefreshTokens() store.RefreshTokens {
	s.Counts.add("RefreshTokens")
	return s.Store.RefreshTokens()
}
func (s CountingStore) Operators() store.Operators {
	s.Counts.add("Operators")
	return s.Store.Operators()
}
func (s CountingStore) HostedLogins() store.HostedLogins {
	s.Counts.add("HostedLogins")
	return s.Store.HostedLogins()
}
func (s CountingStore) Protection() store.Protection {
	s.Counts.add("Protection")
	return s.Store.Protection()
}
