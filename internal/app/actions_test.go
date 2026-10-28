package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestActionsStartupSeed(t *testing.T) {
	actionstest.RequireNode(t)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected registry request %s", r.URL)
		http.NotFound(w, r)
	}))
	defer registry.Close()
	path := filepath.Join(t.TempDir(), "seed.yaml")
	doc := `tenants:
- name: acme
  domains: [acme.example.test]
  actions:
  - name: startup
    code: exports.onExecutePostLogin = async () => {};
    supported_triggers: [{id: post-login}]
    secrets: [{name: KEY, value: value}]
    deploy: true
  triggers:
    post-login:
      bindings: [{ref: {type: action_name, value: startup}}]
`
	if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}, Seed: path, Actions: config.Actions{CacheDir: t.TempDir(), Registry: registry.URL}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tn, err := a.store.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := a.store.Actions().Bindings(context.Background(), tn.ID, "post-login")
	if err != nil || len(bs) != 1 || bs[0].Version.Number != 1 {
		t.Fatalf("startup bindings=%v %v", bs, err)
	}
	master, err := cfg.Security.MasterKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := keys.NewLocalWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	value, err := keys.OpenActionSecret(wrapper, tn.ID, bs[0].Action.ID, "KEY", bs[0].Version.Secrets[0].Sealed)
	if err != nil || value != "value" {
		t.Fatalf("startup secret=%q %v", value, err)
	}
}

// Serve must drain durable Actions jobs and stop the worker before returning.
func TestActionsJobsServeLifecycle(t *testing.T) {
	actionstest.RequireNode(t)
	delivered := make(chan struct{}, 2)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered <- struct{}{} }))
	defer sink.Close()
	seedPath := filepath.Join(t.TempDir(), "seed.yaml")
	doc := fmt.Sprintf(`tenants:
- name: acme
  domains: [acme.example.test]
  actions:
  - name: queued
    code: exports.onExecutePostUserRegistration = async () => { await fetch(%q); };
    supported_triggers: [{id: post-user-registration}]
    deploy: true
  triggers:
    post-user-registration:
      bindings: [{ref: {type: action_name, value: queued}}]
`, sink.URL)
	if err := os.WriteFile(seedPath, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: config.Server{Listen: "127.0.0.1:0", BaseDomain: "example.test", SystemHost: "system.example.test"}, Storage: config.Storage{DSN: "memory://"}, Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}, Seed: seedPath, Actions: config.Actions{CacheDir: t.TempDir(), JobWorkers: 1, JobPollInterval: 10 * time.Millisecond}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tn, err := a.store.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	enqueue := func() {
		t.Helper()
		if err := a.store.WithTx(context.Background(), func(tx store.Store) error {
			return a.actionJobs.Engine.Enqueue(context.Background(), tx, actions.AsyncJob{TenantID: tn.ID, Trigger: actions.TriggerPostUserRegistration, Input: map[string]any{}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not start Actions worker")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop Actions worker")
	}
	enqueue()
	select {
	case <-delivered:
		t.Fatal("worker delivered after Serve returned")
	case <-time.After(50 * time.Millisecond):
	}
}

// Execution observation forwards all real store behavior; it only supplies the
// execution ID because interrupted RunJob deliberately returns no job result.
type executionObservedStore struct {
	store.Store
	records chan *store.Execution
}

func (s executionObservedStore) Actions() store.Actions {
	return executionObservedActions{Actions: s.Store.Actions(), records: s.records}
}

type executionObservedActions struct {
	store.Actions
	records chan *store.Execution
}

func (s executionObservedActions) CreateExecution(ctx context.Context, ex *store.Execution) error {
	if err := s.Actions.CreateExecution(ctx, ex); err != nil {
		return err
	}
	s.records <- ex
	return nil
}

// A canceled attempt's unassociated execution must age out without Management
// workers, while the pending job remains recoverable only after lease expiry.
func TestSweepInterruptedActionsExecution(t *testing.T) {
	ctx := context.Background()
	started := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	st := memory.NewWithClock(func() time.Time { return started })
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	wrapper, err := keys.NewLocalWrapper([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	env := actionstest.NewOffline(t, st, wrapper)
	env.Engine.Now = func() time.Time { return started }
	entered := make(chan struct{}, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{} }))
	defer sink.Close()
	action := env.Deploy(t, "t", actions.TriggerPostUserRegistration, "cancel", fmt.Sprintf(`exports.onExecutePostUserRegistration=async()=>{await fetch(%q);await new Promise(()=>{})}`, sink.URL))
	env.Bind(t, "t", action.Trigger, action)
	if err := st.WithTx(ctx, func(tx store.Store) error {
		return env.Engine.Enqueue(ctx, tx, actions.AsyncJob{TenantID: "t", Trigger: action.Trigger, Input: map[string]any{}})
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.Actions().ClaimJobs(ctx, started, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	records := make(chan *store.Execution, 1)
	env.Engine.Store = executionObservedStore{Store: st, records: records}
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan *store.ActionJob, 1)
	go func() { done <- env.Engine.RunJob(attemptCtx, &claimed[0]) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("attempt did not run")
	}
	cancel()
	select {
	case result := <-done:
		if result != nil {
			t.Fatal("canceled attempt acknowledged")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attempt did not stop")
	}
	var interrupted *store.Execution
	select {
	case interrupted = <-records:
	default:
		t.Fatal("interrupted attempt was not recorded")
	}
	if ex, err := st.Actions().GetExecution(ctx, "t", interrupted.ID); err != nil || len(ex.Results) != 1 || ex.Results[0].ErrorID != "timeout" {
		t.Fatalf("interrupted record: %+v %v", ex, err)
	}
	if count, err := sweep(ctx, st, started.Add(59*time.Second)); err != nil || count != 0 {
		t.Fatalf("early sweep: %d %v", count, err)
	}
	if jobs, err := st.Actions().ClaimJobs(ctx, started.Add(59*time.Second), time.Minute, 1); err != nil || len(jobs) != 0 {
		t.Fatalf("lease released: %v %v", jobs, err)
	}
	if count, err := sweep(ctx, st, started.Add(9*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("premature retention: %d %v", count, err)
	}
	if _, err := st.Actions().GetExecution(ctx, "t", interrupted.ID); err != nil {
		t.Fatalf("young interrupted execution removed: %v", err)
	}
	if err := st.Actions().CreateExecution(ctx, &store.Execution{TenantID: "t", ID: "current", Trigger: action.Trigger, Status: "final", CreatedAt: started.Add(10 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// No Management runner is constructed or started; this is the general sweep.
	aged := started.Add(11 * 24 * time.Hour)
	count, err := sweep(ctx, st, aged)
	if err != nil || count != 1 {
		t.Fatalf("interrupted execution sweep: %d %v; want 1", count, err)
	}
	if _, err := st.Actions().GetExecution(ctx, "t", interrupted.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("orphan retained: %v", err)
	}
	if _, err := st.Actions().GetExecution(ctx, "t", "current"); err != nil {
		t.Fatalf("current execution removed: %v", err)
	}
	recovered, err := st.Actions().ClaimJobs(ctx, aged, time.Minute, 1)
	if err != nil || len(recovered) != 1 || recovered[0].Attempts != 2 || recovered[0].Status != "pending" || len(recovered[0].ExecutionIDs) != 0 {
		t.Fatalf("pending lease recovery: %v %v", recovered, err)
	}
}
