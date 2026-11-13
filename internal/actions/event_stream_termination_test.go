package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Returning from Go is insufficient: cancellation, the sealed deadline and
// successful completion must all stop detached Node network side effects.
//
// Every wait below is measured from when Node reached /start, never from
// enqueue: a cold Node start takes ~80ms alone and several hundred under
// `go test -race ./...` on a CI runner, and must not eat into the windows
// the assertions depend on.
func TestEventStreamExecutionStopsNodeSideEffects(t *testing.T) {
	// Node's late side effect fires this long after /start.
	const lateAfter = 2 * time.Second
	// The short sealed deadline for the deadline modes: long enough for a
	// cold Node start to reach /start, and shorter than lateAfter so that it
	// always expires between /start and /late.
	const shortDeadline = 1500 * time.Millisecond
	for _, mode := range []string{"cancel", "deadline", "failed-cancel", "success-detached"} {
		t.Run(mode, func(t *testing.T) {
			// The sealed deadline is fixed at enqueue, so in the short-deadline
			// modes an unusually slow Node start can still miss it. Such an
			// attempt never reached /start and tests nothing: retry it. A real
			// failure is reported on the attempt that shows it.
			const attempts = 3
			for i := 1; i <= attempts; i++ {
				if !runTermination(t, mode, lateAfter, shortDeadline) {
					return
				}
				t.Logf("attempt %d inconclusive: the sealed deadline ended the job before Node reached /start", i)
			}
			t.Fatalf("Node never reached /start before the sealed deadline in %d attempts", attempts)
		})
	}
}

// runTermination runs one attempt of TestEventStreamExecutionStopsNodeSideEffects
// for mode. It reports true when the attempt was inconclusive: in a
// short-deadline mode the deadline ended the job before Node reached /start.
func runTermination(t *testing.T, mode string, lateAfter, shortDeadline time.Duration) (inconclusive bool) {
	h := newHarness(t)
	started, late := make(chan time.Time, 1), make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			started <- time.Now()
		} else {
			late <- struct{}{}
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	lateMS := lateAfter.Milliseconds()
	code := fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/start');await new Promise(r=>setTimeout(r,%d));await fetch(%q+'/late')}`, receiver.URL, lateMS, receiver.URL)
	if mode == "success-detached" {
		code = fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/start');setTimeout(()=>fetch(%q+'/late'),%d)}`, receiver.URL, receiver.URL, lateMS)
	}
	a := h.action("t1", "event-stream", "terminate", code, nil, false)
	deadline := time.Now().Add(10 * time.Second)
	shortDeadlineMode := mode == "deadline" || mode == "failed-cancel"
	if shortDeadlineMode {
		deadline = time.Now().Add(shortDeadline)
	}
	if mode == "failed-cancel" {
		h.eng.Store = failedCancelStore{h.st}
	}
	_, err := h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_terminate"}`), deadline)
	if err != nil {
		t.Fatal(err)
	}
	claim := claimJob(t, h)
	done := make(chan *store.ActionJob, 1)
	go func() { done <- h.eng.RunJob(context.Background(), &claim) }()
	var startedAt time.Time
	var earlyResult *store.ActionJob
	select {
	case startedAt = <-started:
	case earlyResult = <-done:
		// RunJob returned before /start arrived. /start may still have been
		// received just before the kill, so look once more.
		select {
		case startedAt = <-started:
		default:
			if shortDeadlineMode && earlyResult != nil && earlyResult.Status == "failed" {
				return true
			}
			t.Fatalf("RunJob returned %+v before Node reached /start", earlyResult)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Node never started")
	}
	if mode == "cancel" {
		if err = h.st.Actions().CancelJob(t.Context(), "t1", claim.ID); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "failed-cancel" {
		if err = h.eng.Store.Actions().CancelJob(t.Context(), "t1", claim.ID); err == nil {
			t.Fatal("failure fixture did not fail")
		}
	}
	result := earlyResult
	if result == nil {
		select {
		case result = <-done:
		case <-time.After(stopWithin(shortDeadlineMode, deadline)):
			t.Fatal("RunJob did not stop by deadline")
		}
	}
	want := "failed"
	if mode == "success-detached" {
		want = "done"
	}
	if result == nil || result.Status != want {
		t.Fatalf("result %+v want %s", result, want)
	}
	// Check for a late side effect that already arrived before waiting,
	// so the select below can't pick an expired timer over it.
	select {
	case <-late:
		t.Fatal("Node performed its late side effect before RunJob stopped it")
	default:
	}
	select {
	case <-late:
		t.Fatal("Node performed a side effect after RunJob returned")
	case <-time.After(time.Until(startedAt.Add(lateAfter + 500*time.Millisecond))):
	}
	// A cancelled/terminated process cannot poison the tenant's next attempt.
	h.redeploy(a, `exports.onExecuteEventStream=(e,a)=>{a.cache.set('recovered','yes')}`)
	_, err = h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_next"}`), time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// Complete the old claimed row in deadline/success cases before claiming again.
	if mode != "cancel" {
		_ = h.st.Actions().CancelJob(t.Context(), "t1", claim.ID)
	}
	next := claimJob(t, h)
	if r := finishJob(t, h, &next); r.Status != "done" {
		t.Fatalf("next attempt %+v", r)
	}
	return false
}

// stopWithin bounds how long RunJob may take to return once Node has
// started: until the sealed deadline when that is what stops it, plus slack
// for killing the process on a loaded machine.
func stopWithin(shortDeadlineMode bool, deadline time.Time) time.Duration {
	const slack = 3 * time.Second
	if shortDeadlineMode {
		return time.Until(deadline) + slack
	}
	return slack
}

type failedCancelStore struct{ store.Store }

func (s failedCancelStore) Actions() store.Actions { return failedCancelActions{s.Store.Actions()} }
func (s failedCancelStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(failedCancelStore{tx}) })
}

type failedCancelActions struct{ store.Actions }

func (a failedCancelActions) CancelJob(context.Context, string, string) error {
	return errors.New("cancel storage unavailable")
}

// Isolating Node must retain the documented Go-hosted api.cache across jobs,
// while each execution starts with fresh JavaScript module globals.
func TestEventStreamIsolatedJobsRetainCache(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", "event-stream", "cache", `let calls=0;exports.onExecuteEventStream=(e,a)=>{if(++calls!==1)throw Error('reused process');if(e.message.n===1)a.cache.set('persisted','yes');else if(a.cache.get('persisted')?.value!=='yes')throw Error('lost cache')}`, nil, false)
	for _, n := range []int{1, 2} {
		_, err := h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(fmt.Sprintf(`{"n":%d}`, n)), time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		claim := claimJob(t, h)
		result := finishJob(t, h, &claim)
		if result.Status != "done" {
			t.Fatalf("job %d: %+v", n, result)
		}
	}
}
