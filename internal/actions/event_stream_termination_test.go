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
func TestEventStreamExecutionStopsNodeSideEffects(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "failed-cancel", "success-detached"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			started, late := make(chan struct{}, 1), make(chan struct{}, 1)
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					started <- struct{}{}
				} else {
					late <- struct{}{}
				}
				w.WriteHeader(204)
			}))
			defer receiver.Close()
			code := fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/start');await new Promise(r=>setTimeout(r,500));await fetch(%q+'/late')}`, receiver.URL, receiver.URL)
			if mode == "success-detached" {
				code = fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/start');setTimeout(()=>fetch(%q+'/late'),500)}`, receiver.URL, receiver.URL)
			}
			a := h.action("t1", "event-stream", "terminate", code, nil, false)
			deadline := time.Now().Add(10 * time.Second)
			if mode == "deadline" || mode == "failed-cancel" {
				deadline = time.Now().Add(300 * time.Millisecond)
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
			select {
			case <-started:
			case <-time.After(3 * time.Second):
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
			select {
			case result := <-done:
				want := "failed"
				if mode == "success-detached" {
					want = "done"
				}
				if result == nil || result.Status != want {
					t.Fatalf("result %+v want %s", result, want)
				}
			case <-time.After(time.Second):
				t.Fatal("RunJob did not stop by deadline")
			}
			select {
			case <-late:
				t.Fatal("Node performed a side effect after RunJob returned")
			case <-time.After(650 * time.Millisecond):
			}
			// A cancelled/terminated process cannot poison the tenant's next attempt.
			h.redeploy(a, `exports.onExecuteEventStream=(e,a)=>{a.cache.set('recovered','yes')}`)
			_, err = h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_next"}`), time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			// Complete the old claimed row in deadline/success cases before claiming again.
			if mode != "cancel" {
				_ = h.st.Actions().CancelJob(t.Context(), "t1", claim.ID)
			}
			next := claimJob(t, h)
			result := finishJob(t, h, &next)
			if result.Status != "done" {
				t.Fatalf("next attempt %+v", result)
			}
		})
	}
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
