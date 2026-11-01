package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A second process cancels a leased job: its Node call must stop before the
// sealed ten-second deadline, and its old lease must not revive that job.
func TestEventStreamRunningJobCancellation(t *testing.T) {
	h := newHarness(t)
	started := make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; w.WriteHeader(204) }))
	defer receiver.Close()
	a := h.action("t1", "event-stream", "cancel", fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q);await new Promise(()=>{})}`, receiver.URL), nil, false)
	job, err := h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_cancel"}`), time.Now().Add(10*time.Second))
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
	if err = h.st.Actions().CancelJob(t.Context(), "t1", job.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result == nil || result.Status != "failed" {
			t.Fatalf("cancel result %+v", result)
		}
		if err = h.st.Actions().FinishJob(t.Context(), result, claim.LeaseUntil); !errors.Is(err, store.ErrConflict) {
			t.Fatal("stale finish", err)
		}
	case <-time.After(time.Second):
		t.Fatal("running Node ignored cross-process cancellation")
	}
}

// A sealed deadline expires even if the delivery process vanishes before it
// can cancel the queue row. An expired snapshot must never invoke the handler.
func TestEventStreamExpiredJobDoesNotRun(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", "event-stream", "expired", `exports.onExecuteEventStream=()=>{console.log('MUST_NOT_RUN')}`, nil, false)
	_, err := h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_expired"}`), time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimJob(t, h)
	result := finishJob(t, h, &claim)
	if result.Status != "failed" || strings.Contains(h.logs.String(), "MUST_NOT_RUN") {
		t.Fatalf("expired job %+v %s", result, h.logs.String())
	}
}

// A cancelled claim passed to a worker must be fenced before invoking Node.
func TestEventStreamCancelledBeforeRun(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", "event-stream", "fenced", `exports.onExecuteEventStream=()=>console.log('CANCELLED_ACTION_RAN')`, nil, false)
	// Warm the process so this test catches dispatch before the periodic check.
	if _, err := h.eng.Test(t.Context(), "t1", a.ID, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	j, err := h.eng.EnqueueEventStream(t.Context(), "t1", a.ID, json.RawMessage(`{"id":"evt_fenced"}`), time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimJob(t, h)
	if err = h.st.Actions().CancelJob(t.Context(), "t1", j.ID); err != nil {
		t.Fatal(err)
	}
	result := h.eng.RunJob(t.Context(), &claim)
	if result != nil && result.Status == "done" {
		t.Fatal("cancelled claim executed successfully")
	}
	ex, err := h.st.Actions().ListExecutions(t.Context(), "t1", store.ExecutionFilter{Trigger: "event-stream"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ex)
	if strings.Contains(string(raw), "CANCELLED_ACTION_RAN") {
		t.Fatal("cancelled Action invoked Node")
	}
}
