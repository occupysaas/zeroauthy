//go:build unix

package customdb

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// spinnerSrc calls back with its pid, then keeps the runner busy forever.
const spinnerSrc = `function login(e, p, cb) { cb(null, { pid: process.pid }); setTimeout(() => { while (true) {} }, 50); }`

func runnerPid(t *testing.T, r *NodeRunner, src string) int {
	t.Helper()
	res, err := execLogin(t, r, src)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Pid int }
	if err := json.Unmarshal(res, &out); err != nil || out.Pid == 0 {
		t.Fatalf("result %s", res)
	}
	return out.Pid
}

func waitGone(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runner pid %d still alive after %v", pid, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitRetired(t *testing.T, r *NodeRunner) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.procs)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("process not retired")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunnerCancelledBusyScriptKilled(t *testing.T) {
	r := newRunner(t, config.CustomDB{IdleTimeout: 100 * time.Millisecond})
	r.maxDuration = 700 * time.Millisecond
	pid := runnerPid(t, r, `function login(e, p, cb) { cb(null, { pid: process.pid }); }`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Source: `function login(e, p, cb) { while (true) {} }`, Args: []any{"e", "p"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	// Idle reaping must not retire it: the cancelled request is still pending.
	time.Sleep(300 * time.Millisecond)
	r.mu.Lock()
	n := len(r.procs)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("busy process retired as idle (procs = %d)", n)
	}
	waitGone(t, pid, 5*time.Second) // killed at the request's deadline
}

func TestRunnerReapedSpinnerKilled(t *testing.T) {
	r := newRunner(t, config.CustomDB{IdleTimeout: 100 * time.Millisecond})
	r.reapGrace = 200 * time.Millisecond
	pid := runnerPid(t, r, spinnerSrc)
	waitGone(t, pid, 5*time.Second)
}

func TestRunnerCloseKillsRetiredProcess(t *testing.T) {
	r := newRunner(t, config.CustomDB{IdleTimeout: 100 * time.Millisecond})
	r.reapGrace = time.Hour
	pid := runnerPid(t, r, spinnerSrc)
	waitRetired(t, r)
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("retired spinner already gone: %v", err)
	}
	start := time.Now()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	waitGone(t, pid, time.Second)
}

func TestRunnerCannotSignalOtherProcesses(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	// A same-uid bystander with default SIGTERM/SIGUSR1 actions.
	helper := exec.Command("sleep", "60")
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = helper.Wait(); close(exited) }()
	t.Cleanup(func() { _ = helper.Process.Kill(); <-exited })

	res, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Args: []any{helper.Process.Pid, "p"}, Source: `function login(pid, p, cb) {
	  const out = {};
	  const attempt = (label, f) => { try { f(); out[label] = "allowed"; } catch (err) { out[label] = "denied"; } };
	  attempt("direct", () => process.kill(process.ppid, 0));
	  attempt("helper", () => process.kill(pid));
	  attempt("debug", () => process._debugProcess(pid));
	  attempt("debugEnd", () => process._debugEnd());
	  const real = this.constructor.constructor("return process")();
	  attempt("escaped", () => real.kill(pid));
	  attempt("raw", () => real._kill(pid, 15));
	  attempt("escapedDebug", () => real._debugProcess(pid));
	  attempt("reassigned", () => { delete real.kill; real.kill = () => true; real.kill(pid); });
	  attempt("redefined", () => Object.defineProperty(real, "_debugProcess", { value: () => true }));
	  attempt("priority", () => require("os").setPriority(pid, 19));
	  attempt("escapedPriority", () => real.getBuiltinModule("os").setPriority(pid, 19));
	  attempt("execve", () => real.execve("/bin/true", ["true"], {}));
	  attempt("inspector", () => real.getBuiltinModule("inspector").open(0));
	  try { real.binding("process_methods"); out.binding = "loaded"; } catch (err) { out.binding = "denied:" + err.code; }
	  cb(null, out);
	}`})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signal probe: %s", res)
	var out map[string]string
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"direct", "helper", "debug", "debugEnd", "escaped", "raw", "escapedDebug",
		"reassigned", "redefined", "priority", "escapedPriority", "execve", "inspector"} {
		if out[k] != "denied" {
			t.Errorf("%s = %q, want denied", k, out[k])
		}
	}
	if out["binding"] != "denied:ERR_ACCESS_DENIED" {
		t.Errorf("binding = %q, want denied:ERR_ACCESS_DENIED", out["binding"])
	}
	select {
	case <-exited:
		t.Fatal("the helper process was killed by the script")
	case <-time.After(300 * time.Millisecond):
	}
}
