package noderunner_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// Killing an isolated event-stream call must preserve an unrelated shared call
// in the same tenant and preserve the shared process's version globals.
func TestIsolatedCallCancellationPreservesSharedCall(t *testing.T) {
	p := actionsPool(t, t.TempDir())
	sharedStarted := make(chan struct{}, 1)
	isolatedStarted := make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/shared":
			sharedStarted <- struct{}{}
		case "/isolated":
			isolatedStarted <- struct{}{}
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	code := fmt.Sprintf(`let calls=0;exports.onExecutePostLogin=async(e)=>{++calls;if(e.wait){await fetch(%q+'/shared');await new Promise(r=>setTimeout(r,300))};console.log(calls)}`, receiver.URL)
	shared := actionRequest{Handler: "onExecutePostLogin", VersionKey: "shared", Code: code, Event: map[string]any{"wait": true}}
	sharedDone := make(chan error, 1)
	go func() {
		resp, err := callActionErr(p, "t1", shared)
		if err == nil && (resp.Error != nil || len(resp.Logs) != 1 || resp.Logs[0] != "1") {
			err = fmt.Errorf("shared response %+v", resp)
		}
		sharedDone <- err
	}()
	select {
	case <-sharedStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("shared Node never started")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	isolatedDone := make(chan error, 1)
	req := actionRequest{Handler: "onExecuteEventStream", VersionKey: "isolated", Code: fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/isolated');await new Promise(()=>{})}`, receiver.URL)}
	go func() {
		_, err := p.CallWith(ctx, "t1", req, noderunner.CallOptions{Isolated: true, Budget: time.Second})
		isolatedDone <- err
	}()
	select {
	case <-isolatedStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("isolated Node never started")
	}
	cancel()
	select {
	case err := <-isolatedDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("isolated cancellation did not terminate")
	}
	select {
	case err := <-sharedDone:
		if err != nil {
			t.Fatal("isolated cancellation interrupted shared call", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared call stopped")
	}
	shared.Event = map[string]any{}
	resp, err := callActionErr(p, "t1", shared)
	if err != nil || resp.Error != nil || len(resp.Logs) != 1 || resp.Logs[0] != "2" {
		t.Fatalf("shared process was replaced %+v %v", resp, err)
	}
}

// Default CallWith deliberately lets a cancelled caller's script finish. The
// new opt-in mode must not change that existing behavior for other triggers.
func TestIsolatedCallDoesNotChangeDefaultCancellation(t *testing.T) {
	p := actionsPool(t, t.TempDir())
	started, finished := make(chan struct{}, 1), make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			started <- struct{}{}
		} else {
			finished <- struct{}{}
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	req := actionRequest{Handler: "onExecutePostLogin", VersionKey: "default", Code: fmt.Sprintf(`exports.onExecutePostLogin=async()=>{await fetch(%q+'/start');await new Promise(r=>setTimeout(r,100));await fetch(%q+'/finished')}`, receiver.URL, receiver.URL)}
	go func() { _, err := p.CallWith(ctx, "t1", req, noderunner.CallOptions{Budget: time.Second}); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Node never started")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("default caller cancellation unexpectedly killed Node")
	}
}

// Isolated calls in one tenant are serialized. A waiter cancelled before its
// turn must never start Node, and Close must drain active isolated children.
func TestIsolatedCallBoundAndClose(t *testing.T) {
	p := actionsPool(t, t.TempDir())
	started, forbidden := make(chan struct{}, 1), make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			started <- struct{}{}
		} else {
			forbidden <- struct{}{}
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	first := actionRequest{Handler: "onExecuteEventStream", VersionKey: "first", Code: fmt.Sprintf(`exports.onExecuteEventStream=async()=>{await fetch(%q+'/first');await new Promise(()=>{})}`, receiver.URL)}
	done := make(chan error, 1)
	go func() {
		_, err := p.CallWith(t.Context(), "t1", first, noderunner.CallOptions{Isolated: true, Budget: time.Second * 3})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first never started")
	}
	second := actionRequest{Handler: "onExecuteEventStream", VersionKey: "second", Code: fmt.Sprintf(`exports.onExecuteEventStream=()=>fetch(%q+'/forbidden')`, receiver.URL)}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	if _, err := p.CallWith(ctx, "t1", second, noderunner.CallOptions{Isolated: true, Budget: time.Second}); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, noderunner.ErrTimeout) {
		t.Fatal(err)
	}
	select {
	case <-forbidden:
		t.Fatal("queued isolated call spawned despite tenant bound")
	default:
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, noderunner.ErrUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not drain isolated call")
	}
}
