package noderunner_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// requireNode returns the node on PATH, skipping the test when there is no
// usable Node.js (22.13 or later), or failing it when ZA_REQUIRE_NODE=1.
func requireNode(t *testing.T) string {
	t.Helper()
	reason := ""
	p, err := exec.LookPath("node")
	if err != nil {
		reason = "node not found on PATH"
	} else if out, err := exec.Command(p, "--version").Output(); err != nil {
		reason = "node --version failed: " + err.Error()
	} else if err := noderunner.CheckNodeVersion(strings.TrimSpace(string(out))); err != nil {
		reason = err.Error()
	}
	if reason == "" {
		return p
	}
	if os.Getenv("ZA_REQUIRE_NODE") == "1" {
		t.Fatalf("ZA_REQUIRE_NODE=1 but %s", reason)
	}
	t.Skip(reason)
	return ""
}

// actionsPool starts an Actions pool whose processes may read only
// root/<tenant>, closed at test cleanup.
func actionsPool(t *testing.T, root string) *noderunner.Pool {
	t.Helper()
	requireNode(t)
	p, err := noderunner.New(noderunner.Config{
		Name:   "actions",
		Script: actions.RunnerJS,
		ReadDirs: func(tenant string) []string {
			return []string{filepath.Join(root, tenant)}
		},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// actionRequest is the runner.mjs request.
type actionRequest struct {
	API            []string          `json:"api"`
	UnsupportedAPI []string          `json:"unsupported_api"`
	VersionKey     string            `json:"version_key"`
	Code           string            `json:"code"`
	DepsRoot       string            `json:"deps_root"`
	Handler        string            `json:"handler"`
	Event          map[string]any    `json:"event"`
	Secrets        map[string]string `json:"secrets"`
	Cache          map[string]any    `json:"cache"`
	Roles          []any             `json:"roles"`
	State          map[string]any    `json:"state"`
	Hostname       string            `json:"hostname"`
}

type command struct {
	Op   string            `json:"op"`
	Args []json.RawMessage `json:"args"`
}

type actionResponse struct {
	Commands []command `json:"commands"`
	Logs     []string  `json:"logs"`
	Error    *struct {
		Message string `json:"message"`
		Stack   string `json:"stack"`
	} `json:"error"`
}

func callAction(t *testing.T, p *noderunner.Pool, tenant string, req actionRequest) actionResponse {
	t.Helper()
	resp, err := callActionErr(p, tenant, req)
	if err != nil {
		t.Fatalf("%s: %v", tenant, err)
	}
	return resp
}

func callActionErr(p *noderunner.Pool, tenant string, req actionRequest) (actionResponse, error) {
	if req.Handler == "" {
		req.Handler = "onExecutePostLogin"
	}
	if req.Event == nil {
		req.Event = map[string]any{}
	}
	// Raw runner probes must supply the same explicit capability contract as
	// the engine; an omitted list intentionally exposes no Action APIs.
	if req.API == nil {
		for _, trigger := range actionsrules.Inventory().Triggers {
			if trigger.Handler != req.Handler && trigger.ContinueHandler != req.Handler {
				continue
			}
			for _, member := range trigger.API {
				req.API = append(req.API, member.Name)
				if member.Support == "unsupported" {
					req.UnsupportedAPI = append(req.UnsupportedAPI, member.Name)
				}
			}
			break
		}
	}
	raw, err := p.Call(context.Background(), tenant, req)
	if err != nil {
		return actionResponse{}, err
	}
	var resp actionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return actionResponse{}, err
	}
	return resp, nil
}

// claim returns the value of the first accessToken.setCustomClaim(name, …).
func claim(t *testing.T, resp actionResponse, name string) json.RawMessage {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("handler failed: %s\n%s", resp.Error.Message, resp.Error.Stack)
	}
	for _, c := range resp.Commands {
		if c.Op == "accessToken.setCustomClaim" && len(c.Args) == 2 && string(c.Args[0]) == `"`+name+`"` {
			return c.Args[1]
		}
	}
	t.Fatalf("no claim %q in %+v", name, resp.Commands)
	return nil
}

// TestActionsRunnerIsolation: tenants never share a process, secrets or
// cache; a busy Action is killed at the 20 s flow budget, failing only that
// tenant's in-flight Actions calls; the tenant's custom database process is
// separate and unaffected; child processes, workers and addons are denied.
func TestActionsRunnerIsolation(t *testing.T) {
	root := t.TempDir()
	for _, tenant := range []string{"t1", "t2"} {
		if err := os.MkdirAll(filepath.Join(root, tenant), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := actionsPool(t, root)

	// Secrets and cache reach only the call that carries them; a value
	// stashed on the real global object stays in the tenant's process.
	stash := `exports.onExecutePostLogin = async (event, api) => {
	  const host = api.constructor.constructor("return globalThis")();
	  if (event.secrets.K) host.stash = event.secrets.K;
	  api.cache.set("seen", String(event.secrets.K));
	  api.accessToken.setCustomClaim("probe", {
	    pid: api.constructor.constructor("return process")().pid,
	    stash: host.stash ?? null, secret: event.secrets.K ?? null, cached: api.cache.get("c")?.value ?? null,
	  });
	};`
	r1 := callAction(t, p, "t1", actionRequest{VersionKey: "v1", Code: stash,
		Secrets: map[string]string{"K": "one-secret"}, Cache: map[string]any{"c": map[string]any{"value": "t1-cached"}}})
	r2 := callAction(t, p, "t2", actionRequest{VersionKey: "v1", Code: stash})
	var p1, p2 struct {
		Pid                   int
		Stash, Secret, Cached *string
	}
	if err := json.Unmarshal(claim(t, r1, "probe"), &p1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(claim(t, r2, "probe"), &p2); err != nil {
		t.Fatal(err)
	}
	if p1.Pid == p2.Pid {
		t.Fatalf("tenants share process %d", p1.Pid)
	}
	if p1.Secret == nil || *p1.Secret != "one-secret" || p1.Cached == nil || *p1.Cached != "t1-cached" {
		t.Fatalf("t1 probe = %+v", p1)
	}
	if p2.Stash != nil || p2.Secret != nil || p2.Cached != nil {
		t.Fatalf("t2 sees t1 state: %+v", p2)
	}
	r1again := callAction(t, p, "t1", actionRequest{VersionKey: "v1", Code: stash})
	var p1again struct{ Stash *string }
	_ = json.Unmarshal(claim(t, r1again, "probe"), &p1again)
	if p1again.Stash == nil || *p1again.Stash != "one-secret" {
		t.Fatalf("stash probe ineffective: %+v", p1again)
	}

	// Escape hatches are denied by --permission.
	denied := callAction(t, p, "t1", actionRequest{VersionKey: "v-denied", Code: `exports.onExecutePostLogin = async (event, api) => {
	  const out = {};
	  const proc = api.constructor.constructor("return process")();
	  const attempt = async (label, f) => { try { await f(); out[label] = "allowed"; } catch (e) { out[label] = "denied:" + (e.code || e.message); } };
	  await attempt("require", () => require("child_process").execFileSync("/bin/true"));
	  await attempt("child", () => proc.getBuiltinModule("child_process").execFileSync("/bin/true"));
	  await attempt("worker", () => new (proc.getBuiltinModule("worker_threads").Worker)("1", { eval: true }));
	  await attempt("addon", () => proc.dlopen({ exports: {} }, "/nonexistent.node"));
	  await attempt("wasi", () => new (proc.getBuiltinModule("wasi").WASI)({ version: "preview1" }));
	  await attempt("kill", () => proc.kill(proc.ppid, 0));
	  api.accessToken.setCustomClaim("probe", out);
	};`})
	var esc map[string]string
	if err := json.Unmarshal(claim(t, denied, "probe"), &esc); err != nil {
		t.Fatal(err)
	}
	t.Logf("escape probe: %v", esc)
	for _, k := range []string{"require", "child", "worker", "addon", "wasi", "kill"} {
		if !strings.HasPrefix(esc[k], "denied") {
			t.Errorf("%s = %q, want denied", k, esc[k])
		}
	}

	// A customdb pool for the same tenant, separate from the Actions pool.
	requireNode(t)
	cdb, err := customdb.NewNodeRunner(config.CustomDB{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cdb.Close() })
	cdbLogin := func() (json.RawMessage, error) {
		return cdb.Execute(context.Background(), customdb.Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
			Args: []any{"e", "p"}, Source: `function login(e, p, cb) { setTimeout(() => cb(null, { pid: process.pid }), 50); }`})
	}
	before, err := cdbLogin()
	if err != nil {
		t.Fatal(err)
	}

	// A 25 s busy loop is killed at the 20 s budget.
	busy := `exports.onExecutePostLogin = async () => { const end = Date.now() + 25000; while (Date.now() < end) {} };`
	slow := `exports.onExecutePostLogin = async (event, api) => { await new Promise((r) => setTimeout(r, 200)); api.access.deny("x"); };`
	start := time.Now()
	var wg sync.WaitGroup
	var busyErr, inflightErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, busyErr = callActionErr(p, "t1", actionRequest{VersionKey: "busy", Code: busy})
	}()
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		_, inflightErr = callActionErr(p, "t1", actionRequest{VersionKey: "slow", Code: slow})
	}()
	time.Sleep(time.Second)
	// Other tenants and the tenant's custom database keep working meanwhile.
	if r := callAction(t, p, "t2", actionRequest{VersionKey: "slow", Code: slow}); len(r.Commands) != 1 || r.Commands[0].Op != "access.deny" {
		t.Fatalf("t2 during t1's busy loop: %+v", r)
	}
	during, err := cdbLogin()
	if err != nil {
		t.Fatalf("customdb during t1's busy Action: %v", err)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if !errors.Is(busyErr, noderunner.ErrTimeout) {
		t.Fatalf("busy call err = %v, want ErrTimeout", busyErr)
	}
	if elapsed < noderunner.DefaultBudget-time.Second || elapsed > noderunner.DefaultBudget+5*time.Second {
		t.Fatalf("busy call ended after %v, want about %v", elapsed, noderunner.DefaultBudget)
	}
	if inflightErr == nil {
		t.Fatal("t1's other in-flight call survived the kill")
	}
	after, err := cdbLogin()
	if err != nil {
		t.Fatalf("customdb after t1's Action timeout: %v", err)
	}
	if string(before) != string(during) || string(before) != string(after) {
		t.Fatalf("customdb process changed: %s %s %s", before, during, after)
	}
	// t1 gets a fresh Actions process.
	if r := callAction(t, p, "t1", actionRequest{VersionKey: "slow", Code: slow}); len(r.Commands) != 1 {
		t.Fatalf("t1 after kill: %+v", r)
	}
}

// TestActionsRunnerVersions: one vm context per version_key, and require
// resolves only inside that version's deps_root/node_modules.
func TestActionsRunnerVersions(t *testing.T) {
	root := t.TempDir()
	withPad := filepath.Join(root, "t1", "builds", "a")
	without := filepath.Join(root, "t1", "builds", "b")
	for _, d := range []string{filepath.Join(withPad, "node_modules", "za-pad"), filepath.Join(without, "node_modules")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(withPad, "node_modules", "za-pad", "index.js"), []byte(`module.exports = (s) => "[" + s + "]";`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := actionsPool(t, root)
	code := `let calls = 0;
	exports.onExecutePostLogin = async (event, api) => {
	  calls++;
	  let pad;
	  try { pad = require("za-pad")("x"); } catch (e) { pad = "error:" + e.message; }
	  let rel;
	  try { require("./x"); rel = "loaded"; } catch (e) { rel = "denied"; }
	  api.idToken.setCustomClaim("n", calls);
	  api.accessToken.setCustomClaim("probe", { calls, pad, rel, crypto: typeof require("node:crypto").randomUUID });
	};`
	type probe struct {
		Calls    int
		Pad, Rel string
		Crypto   string
	}
	get := func(key, deps string) probe {
		t.Helper()
		var out probe
		if err := json.Unmarshal(claim(t, callAction(t, p, "t1", actionRequest{VersionKey: key, Code: code, DepsRoot: deps}), "probe"), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := get("a", withPad); got.Calls != 1 || got.Pad != "[x]" || got.Rel != "denied" || got.Crypto != "function" {
		t.Fatalf("a#1 = %+v", got)
	}
	if got := get("a", withPad); got.Calls != 2 {
		t.Fatalf("a#2 = %+v, want the same context", got)
	}
	if got := get("b", without); got.Calls != 1 || !strings.HasPrefix(got.Pad, "error:") {
		t.Fatalf("b = %+v, want a fresh context without za-pad", got)
	}
	// Errors come back as {message, stack}; a missing handler is an error.
	resp := callAction(t, p, "t1", actionRequest{VersionKey: "c", Code: `exports.onExecutePostLogin = async () => { throw new Error("boom"); };`})
	if resp.Error == nil || resp.Error.Message != "boom" || resp.Error.Stack == "" {
		t.Fatalf("throw: %+v", resp.Error)
	}
	resp = callAction(t, p, "t1", actionRequest{VersionKey: "c", Handler: "onExecuteCredentialsExchange", Code: `exports.onExecutePostLogin = async () => {};`})
	if resp.Error == nil {
		t.Fatal("missing handler did not fail")
	}
	// Unsupported api namespaces throw rather than being silently skipped.
	resp = callAction(t, p, "t1", actionRequest{VersionKey: "d", Code: `exports.onExecutePostLogin = async (event, api) => { api.multifactor.enable("any"); };`})
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "not supported") {
		t.Fatalf("multifactor: %+v", resp)
	}
	// console output is captured per call.
	resp = callAction(t, p, "t1", actionRequest{VersionKey: "e", Code: `exports.onExecutePostLogin = async () => { console.log("hello", { a: 1 }); };`})
	if len(resp.Logs) != 1 || resp.Logs[0] != `hello {"a":1}` {
		t.Fatalf("logs = %q", resp.Logs)
	}
}

// TestCallRejectsReservedID: the Pool owns the request "id"; a request that
// carries one fails at once instead of waiting for an answer that never
// matches.
func TestCallRejectsReservedID(t *testing.T) {
	p := actionsPool(t, t.TempDir())
	for _, req := range []any{
		map[string]any{"id": 7, "handler": "onExecutePostLogin"},
		json.RawMessage(`{"handler":"onExecutePostLogin", "id" :null}`),
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		_, err := p.CallWith(ctx, "t1", req, noderunner.CallOptions{Budget: 10 * time.Second})
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, noderunner.ErrTimeout) {
			t.Fatalf("request with id: err = %v, want an immediate refusal", err)
		}
		if !strings.Contains(err.Error(), `"id"`) || time.Since(start) > time.Second {
			t.Fatalf("err = %v after %v", err, time.Since(start))
		}
	}
}
