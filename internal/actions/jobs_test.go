package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func enqueueJob(t *testing.T, h *harness, trigger string, input any) {
	t.Helper()
	if err := h.st.WithTx(context.Background(), func(tx store.Store) error {
		return h.eng.Enqueue(context.Background(), tx, actions.AsyncJob{TenantID: "t1", Trigger: trigger, Input: input})
	}); err != nil {
		t.Fatal(err)
	}
}
func claimJob(t *testing.T, h *harness) store.ActionJob {
	t.Helper()
	jobs, err := h.st.Actions().ClaimJobs(context.Background(), h.clock(), time.Minute, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v %v", jobs, err)
	}
	return jobs[0]
}
func finishJob(t *testing.T, h *harness, j *store.ActionJob) *store.ActionJob {
	t.Helper()
	next := h.eng.RunJob(context.Background(), j)
	if next == nil {
		t.Fatal("attempt unfinished")
	}
	if err := h.st.Actions().FinishJob(context.Background(), next, j.LeaseUntil); err != nil {
		t.Fatal(err)
	}
	return next
}

// Removing transaction use or reloading bindings at dispatch loses the original event/code.
func TestJobsEnqueueInTx(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.action("t1", actions.TriggerPostUserRegistration, "registered", `exports.onExecutePostUserRegistration=(e)=>{if(e.user.email!=='original')throw Error('changed event')}`, nil, false)
	h.bind("t1", a.Trigger, a)
	rollback := errors.New("rollback")
	if err := h.st.WithTx(ctx, func(tx store.Store) error {
		if err := h.eng.Enqueue(ctx, tx, actions.AsyncJob{TenantID: "t1", Trigger: a.Trigger, Input: map[string]any{"user": map[string]any{"email": "original"}}}); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock(), time.Minute, 10); len(js) != 0 {
		t.Fatal("rolled-back job visible")
	}
	input := map[string]any{"user": map[string]any{"email": "original"}}
	enqueueJob(t, h, a.Trigger, input)
	input["user"] = nil
	h.redeploy(a, `exports.onExecutePostUserRegistration=()=>{throw Error('new version')}`)
	h.bind("t1", a.Trigger)
	j := claimJob(t, h)
	if n := finishJob(t, h, &j); n.Status != "done" {
		t.Fatalf("snapshot: %+v", n)
	}
	enqueueJob(t, h, a.Trigger, map[string]any{})
	if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock().Add(time.Hour), time.Minute, 10); len(js) != 0 {
		t.Fatal("unbound flow enqueued or completed job reclaimed")
	}
}

// A once-only trigger must record failure but never schedule another attempt.
func TestJobsRunOnce(t *testing.T) {
	for _, tr := range []string{actions.TriggerPostUserRegistration, actions.TriggerPostChangePassword} {
		t.Run(tr, func(t *testing.T) {
			h := newHarness(t)
			handler := "onExecutePostUserRegistration"
			if tr == actions.TriggerPostChangePassword {
				handler = "onExecutePostChangePassword"
			}
			a := h.action("t1", tr, "fail", fmt.Sprintf(`exports.%s=()=>{throw Error('failure')}`, handler), nil, false)
			h.bind("t1", tr, a)
			enqueueJob(t, h, tr, map[string]any{})
			j := claimJob(t, h)
			n := finishJob(t, h, &j)
			if n.Status != "failed" || len(n.ExecutionIDs) != 1 {
				t.Fatalf("once result: %+v", n)
			}
			ex, err := h.st.Actions().GetExecution(context.Background(), "t1", n.ExecutionIDs[0])
			if err != nil || len(ex.Results) != 1 || ex.Results[0].ErrorID != "runtime_error" {
				t.Fatalf("record: %+v %v", ex, err)
			}
			if !strings.Contains(h.logs.String(), n.ExecutionIDs[0]) {
				t.Fatal("missing execution ID log")
			}
			if js, _ := h.st.Actions().ClaimJobs(context.Background(), h.clock().Add(24*time.Hour), time.Minute, 1); len(js) != 0 {
				t.Fatal("once job retried")
			}
		})
	}
}

// Retry delays must be capped after five retries; final notification call wins.
func TestJobsEmailRetry(t *testing.T) {
	for _, tc := range []struct{ name, code, status string }{{"retry", `a.notification.retry('again')`, "pending"}, {"throw", `throw Error('oops')`, "pending"}, {"timeout", `await new Promise(()=>{})`, "pending"}, {"drop-last", `a.notification.retry('first');a.notification.drop('last')`, "dropped"}, {"retry-last", `a.notification.drop('first');a.notification.retry('last')`, "pending"}, {"sent", `return`, "done"}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.name == "timeout" {
				h.eng.FlowBudget = 100 * time.Millisecond
			}
			a := h.action("t1", actions.TriggerCustomEmailProvider, "email", `exports.onExecuteCustomEmailProvider=async(e,a)=>{`+tc.code+`}`, nil, false)
			h.bind("t1", a.Trigger, a)
			enqueueJob(t, h, a.Trigger, map[string]any{})
			delays := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute}
			for i := 0; i < 6; i++ {
				j := claimJob(t, h)
				n := finishJob(t, h, &j)
				want := tc.status
				if i == 5 && want == "pending" {
					want = "failed"
				}
				if n.Status != want || len(n.ExecutionIDs) != i+1 {
					t.Fatalf("attempt %d: %+v want %s", i+1, n, want)
				}
				ex, err := h.st.Actions().GetExecution(context.Background(), "t1", n.ExecutionIDs[len(n.ExecutionIDs)-1])
				if err != nil || len(ex.Results) == 0 || ex.Results[0].JobID != j.ID || ex.Results[0].JobAttempt != i+1 {
					t.Fatalf("attempt metadata: %+v %v", ex, err)
				}
				if want != "pending" {
					if js, _ := h.st.Actions().ClaimJobs(context.Background(), h.clock().Add(24*time.Hour), time.Minute, 1); len(js) != 0 {
						t.Fatal("terminal job reclaimed")
					}
					break
				}
				if !n.NextAt.Equal(h.clock().Add(delays[i])) {
					t.Fatalf("attempt %d at %s", i, n.NextAt)
				}
				if js, _ := h.st.Actions().ClaimJobs(context.Background(), n.NextAt.Add(-time.Millisecond), time.Minute, 1); len(js) != 0 {
					t.Fatal("retry claimed early")
				}
				h.advance(delays[i])
			}
		})
	}
}

// Stopping a running worker must leave its lease; only expiry permits redelivery.
func TestJobsLeaseExpiry(t *testing.T) {
	h := newHarness(t)
	var calls atomic.Int32
	entered := make(chan struct{}, 2)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		entered <- struct{}{}
		if n == 1 {
			fmt.Fprint(w, "wait")
		} else {
			fmt.Fprint(w, "ok")
		}
	}))
	defer sink.Close()
	a := h.action("t1", actions.TriggerPostUserRegistration, "wait", fmt.Sprintf(`exports.onExecutePostUserRegistration=async()=>{let r=await fetch(%q);if(await r.text()==='wait')await new Promise(()=>{})}`, sink.URL), nil, false)
	h.bind("t1", a.Trigger, a)
	enqueueJob(t, h, a.Trigger, map[string]any{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w := &actions.Worker{Engine: h.eng, Store: h.st, Workers: 1, Poll: time.Millisecond, Lease: time.Minute}
	go func() { defer close(done); w.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
	if js, _ := h.st.Actions().ClaimJobs(context.Background(), h.clock().Add(59*time.Second), time.Minute, 1); len(js) != 0 {
		t.Fatal("lease released on cancellation")
	}
	h.advance(time.Minute)
	j := claimJob(t, h)
	if j.Attempts != 2 {
		t.Fatalf("attempts=%d", j.Attempts)
	}
	if n := finishJob(t, h, &j); n.Status != "done" {
		t.Fatal(n.Status)
	}
	if calls.Load() != 2 {
		t.Fatalf("deliveries %d", calls.Load())
	}
	stale := j
	stale.LeaseUntil = stale.LeaseUntil.Add(-time.Minute)
	stale.Status = "failed"
	if err := h.st.Actions().FinishJob(context.Background(), &stale, stale.LeaseUntil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale completion: %v", err)
	}
}

func TestJobsCap(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", actions.TriggerPostUserRegistration, "cap", `exports.onExecutePostUserRegistration=()=>{}`, nil, false)
	h.bind("t1", a.Trigger, a)
	// One real Enqueue at the boundary avoids quadratic repeated sealing in this store fixture.
	for i := 0; i < 10000; i++ {
		if err := h.st.Actions().EnqueueJob(context.Background(), &store.ActionJob{TenantID: "t1", ID: fmt.Sprint(i), Trigger: a.Trigger}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.eng.Enqueue(context.Background(), h.st, actions.AsyncJob{TenantID: "t1", Trigger: a.Trigger, Input: map[string]any{}}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("cap: %v", err)
	}
}
func TestJobsPurge(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", actions.TriggerPostUserRegistration, "purge", `exports.onExecutePostUserRegistration=()=>{}`, nil, false)
	h.bind("t1", a.Trigger, a)
	enqueueJob(t, h, a.Trigger, map[string]any{})
	j := claimJob(t, h)
	n := finishJob(t, h, &j)
	if count, err := actions.PurgeJobs(context.Background(), h.st, time.Now().Add(9*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("early purge: %d %v", count, err)
	}
	if count, err := actions.PurgeJobs(context.Background(), h.st, time.Now().Add(11*24*time.Hour)); err != nil || count != 1 {
		t.Fatalf("purge: %d %v", count, err)
	}
	if _, err := h.st.Actions().GetExecution(context.Background(), "t1", n.ExecutionIDs[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retained execution: %v", err)
	}
}

// A durable job owns both immutable code snapshots and sealed secret domains after deletion.
func TestJobsModulesTombstone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var got atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("answer") == "old-module:module-secret:old-dependency:action-secret" {
			got.Add(1)
		} else {
			t.Errorf("unexpected queued result: %s", r.URL)
		}
	}))
	defer sink.Close()
	m, _ := moduleFixture(t, h, "t1", "util", `exports.value=()=>['old-module',actions.secrets.KEY,require('private-dep')].join(':')`, map[string]string{"KEY": "module-secret"})
	m.Dependencies = []store.Dependency{{Name: "private-dep", Version: "1.0.0"}}
	m.DraftBuildID = installedFixture(t, h, "t1", "private-dep", `module.exports='old-dependency'`)
	if err := h.st.Actions().UpdateModule(ctx, m); err != nil {
		t.Fatal(err)
	}
	mv, err := h.st.Actions().PublishModule(ctx, "t1", m.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := h.action("t1", actions.TriggerPostUserRegistration, "pinned", fmt.Sprintf(`exports.onExecutePostUserRegistration=async(e)=>{await fetch(%q+'?answer='+encodeURIComponent(require('actions:util').value()+':'+e.secrets.KEY))}`, sink.URL), map[string]string{"KEY": "action-secret"}, true)
	av := pinModule(t, h, a, m, mv)
	h.bind("t1", a.Trigger, a)
	enqueueJob(t, h, a.Trigger, map[string]any{})
	j := claimJob(t, h)
	if len(j.ModuleVersionIDs) != 1 || j.ModuleVersionIDs[0] != mv.ID {
		t.Fatalf("module retention pins: %v", j.ModuleVersionIDs)
	}
	if strings.Contains(string(j.Sealed), "action-secret") || strings.Contains(string(j.Sealed), "module-secret") {
		t.Fatal("plaintext in envelope")
	}
	if err := h.st.Actions().DeleteAction(ctx, "t1", a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.Actions().GetVersion(ctx, "t1", a.ID, av.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("parent version retained: %v", err)
	}
	if err := h.st.Actions().DeleteModule(ctx, "t1", m.ID); err != nil {
		t.Fatal(err)
	}
	// Pending jobs retain tombstones in addition to carrying self-contained snapshots.
	if _, err := h.st.Actions().GetModuleVersion(ctx, "t1", m.ID, mv.ID); err != nil {
		t.Fatal(err)
	}
	if n := finishJob(t, h, &j); n.Status != "done" || got.Load() != 1 {
		t.Fatalf("queued snapshots: %s %d", n.Status, got.Load())
	}
	if count, err := actions.PurgeJobs(ctx, h.st, time.Now().Add(11*24*time.Hour)); err != nil || count != 1 {
		t.Fatalf("purge job pin: %d %v", count, err)
	}
	if _, err := h.st.Actions().GetModuleVersion(ctx, "t1", m.ID, mv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unpinned tombstone retained: %v", err)
	}
}

func TestJobsEnvelopeIntegrity(t *testing.T) {
	for _, fault := range []string{"tenant", "trigger", "id", "label", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			a := h.action("t1", actions.TriggerPostUserRegistration, "sealed", `exports.onExecutePostUserRegistration=()=>{}`, nil, false)
			h.bind("t1", a.Trigger, a)
			enqueueJob(t, h, a.Trigger, map[string]any{})
			j := claimJob(t, h)
			switch fault {
			case "tenant":
				j.TenantID = "t2"
			case "trigger":
				j.Trigger = actions.TriggerPostChangePassword
			case "id":
				j.ID = "other"
			case "corrupt":
				j.Sealed[0] ^= 1
			case "label":
				var err error
				j.Sealed, err = keys.SealBound(h.w, "action-continue/v1", []string{j.TenantID, j.ID, j.Trigger}, []byte(`{}`))
				if err != nil {
					t.Fatal(err)
				}
			}
			n := h.eng.RunJob(context.Background(), &j)
			if n == nil || n.Status != "failed" || len(n.ExecutionIDs) != 1 {
				t.Fatalf("invalid envelope: %+v", n)
			}
			ex, err := h.st.Actions().GetExecution(context.Background(), j.TenantID, n.ExecutionIDs[0])
			if err != nil || len(ex.Results) != 1 || ex.Results[0].JobID != j.ID || ex.Results[0].JobAttempt != j.Attempts {
				t.Fatalf("invalid envelope attempt: %+v %v", ex, err)
			}
		})
	}
}

// Authenticated but incomplete or mismatched snapshots must fail closed.
func TestJobsModuleSnapshotIntegrity(t *testing.T) {
	for _, fault := range []string{"missing", "wrong-tenant", "wrong-module", "wrong-version", "wrong-number", "extra"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			m, mv := moduleFixture(t, h, "t1", "util", `exports.value=()=>1`, nil)
			a := h.action("t1", actions.TriggerPostUserRegistration, "snapshot", `exports.onExecutePostUserRegistration=()=>require('actions:util').value()`, nil, true)
			pinModule(t, h, a, m, mv)
			h.bind("t1", a.Trigger, a)
			enqueueJob(t, h, a.Trigger, map[string]any{})
			j := claimJob(t, h)
			plain, err := keys.OpenBound(h.w, "action-job/v1", []string{j.TenantID, j.ID, j.Trigger}, j.Sealed)
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Units []struct {
					Name, ActionID, VersionKey, Code, BuildID string
					Secrets                                   []store.ActionSecret
					Modules                                   []store.ModuleRef
					ModuleVersions                            []store.ActionModuleVersion
				}
				Input map[string]any
			}
			if err := json.Unmarshal(plain, &payload); err != nil {
				t.Fatal(err)
			}
			versions := payload.Units[0].ModuleVersions
			switch fault {
			case "missing":
				versions = nil
			case "wrong-tenant":
				versions[0].TenantID = "t2"
			case "wrong-module":
				versions[0].ModuleID = "other"
			case "wrong-version":
				versions[0].ID = "other"
			case "wrong-number":
				versions[0].Number++
			case "extra":
				versions = append(versions, versions[0])
			}
			payload.Units[0].ModuleVersions = versions
			plain, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			j.Sealed, err = keys.SealBound(h.w, "action-job/v1", []string{j.TenantID, j.ID, j.Trigger}, plain)
			if err != nil {
				t.Fatal(err)
			}
			n := h.eng.RunJob(ctx, &j)
			if n == nil || n.Status != "failed" {
				t.Fatalf("invalid snapshots ran: %+v", n)
			}
		})
	}
}

// A recorded drop is terminal even when a later bound Action fails, and an
// attempt in which any Action completed is never retried: a retry would run
// the completed Action again and could deliver the email twice (I-1).
func TestJobsEmailMultipleBindingsNeverRerun(t *testing.T) {
	for _, tc := range []struct{ name, first, second, status string }{
		{"drop-then-throw", `a.notification.drop('bad address')`, `throw Error('later failure')`, "dropped"},
		{"drop-then-retry", `a.notification.drop('bad address')`, `a.notification.retry('later')`, "dropped"},
		{"sent-then-throw", `return`, `throw Error('later failure')`, "failed"},
		{"sent-then-retry", `return`, `a.notification.retry('later')`, "failed"},
		{"sent-then-timeout", `return`, `await new Promise(()=>{})`, "failed"},
		{"retry-then-throw", `a.notification.retry('first')`, `throw Error('later failure')`, "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.name == "sent-then-timeout" {
				h.eng.FlowBudget = time.Second
			}
			var deliveries atomic.Int32
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { deliveries.Add(1) }))
			defer sink.Close()
			a := h.action("t1", actions.TriggerCustomEmailProvider, "deliver", fmt.Sprintf(`exports.onExecuteCustomEmailProvider=async(e,a)=>{await fetch(%q);%s}`, sink.URL, tc.first), nil, false)
			b := h.action("t1", actions.TriggerCustomEmailProvider, "second", `exports.onExecuteCustomEmailProvider=async(e,a)=>{`+tc.second+`}`, nil, false)
			h.bind("t1", a.Trigger, a, b)
			enqueueJob(t, h, a.Trigger, map[string]any{})
			j := claimJob(t, h)
			n := finishJob(t, h, &j)
			if n.Status != tc.status || len(n.ExecutionIDs) != 1 {
				t.Fatalf("status %q want %q (executions %d)", n.Status, tc.status, len(n.ExecutionIDs))
			}
			if tc.status != "pending" {
				if js, _ := h.st.Actions().ClaimJobs(context.Background(), h.clock().Add(24*time.Hour), time.Minute, 1); len(js) != 0 {
					t.Fatal("terminal job reclaimed")
				}
			}
			if got := deliveries.Load(); got != 1 {
				t.Fatalf("deliveries %d", got)
			}
		})
	}
}

// An envelope that cannot open can never succeed; it must not be retried (M-2).
func TestJobsEmailCorruptEnvelopeNotRetried(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", actions.TriggerCustomEmailProvider, "email", `exports.onExecuteCustomEmailProvider=()=>{}`, nil, false)
	h.bind("t1", a.Trigger, a)
	enqueueJob(t, h, a.Trigger, map[string]any{})
	j := claimJob(t, h)
	j.Sealed[0] ^= 1
	n := h.eng.RunJob(context.Background(), &j)
	if n == nil || n.Status != "failed" || len(n.ExecutionIDs) != 1 {
		t.Fatalf("corrupt envelope: %+v", n)
	}
}
