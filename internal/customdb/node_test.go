package customdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// execLogin runs a login script on tenant t1 / connection c1 with no configuration.
func execLogin(t *testing.T, r *NodeRunner, src string) (json.RawMessage, error) {
	t.Helper()
	return r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Source: src, Args: []any{"a@x.test", "pw"}})
}

func mustJSON(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var got, exp any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("result %q is not JSON: %v", raw, err)
	}
	if err := json.Unmarshal([]byte(want), &exp); err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(got)
	e, _ := json.Marshal(exp)
	if !bytes.Equal(g, e) {
		t.Fatalf("result = %s, want %s", g, e)
	}
}

func scriptErr(t *testing.T, err error, kind string) *ScriptError {
	t.Helper()
	var se *ScriptError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *ScriptError", err)
	}
	if se.Kind != kind {
		t.Fatalf("kind = %q (%q), want %q", se.Kind, se.Message, kind)
	}
	return se
}

func TestRunnerLoginProfile(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	ctx := context.Background()
	src := `function login(email, password, callback) {
	  if (password !== "pw") return callback(new WrongUsernameOrPasswordError(email, "bad password"));
	  callback(null, { user_id: "42", email: email, app_metadata: { k: configuration.K } });
	}`
	req := Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Source: src,
		Config: map[string]string{"K": "v"}, Args: []any{"a@x.test", "pw"}}
	res, err := r.Execute(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"42","email":"a@x.test","app_metadata":{"k":"v"}}`)

	req.Args = []any{"a@x.test", "nope"}
	_, err = r.Execute(ctx, req)
	se := scriptErr(t, err, KindWrongCredentials)
	if se.Code != "a@x.test" || se.Message != "bad password" {
		t.Fatalf("got %+v", se)
	}
}

func TestRunnerNullResult(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	res, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "get_user",
		Source: `function getByEmail(email, callback) { callback(null); }`, Args: []any{"a@x.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(res) != "null" {
		t.Fatalf("result = %s, want null", res)
	}
}

func TestRunnerErrorKinds(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	se := scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) { cb(new ValidationError("user_exists", "m")); }`)), KindValidation)
	if se.Code != "user_exists" || se.Message != "m" {
		t.Fatalf("validation: %+v", se)
	}
	se = scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) { cb(new UnauthorizedError("blocked here")); }`)), KindUnauthorized)
	if se.Message != "blocked here" {
		t.Fatalf("unauthorized: %+v", se)
	}
	se = scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) { cb(new Error("db down")); }`)), KindError)
	if se.Message != "db down" {
		t.Fatalf("error: %+v", se)
	}
	scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) { throw new Error("thrown"); }`)), KindError)
	se = scriptErr(t, must2(execLogin(t, r, `async function login(e, p, cb) { await null; throw new Error("rejected"); }`)), KindError)
	if se.Message != "rejected" {
		t.Fatalf("rejected: %+v", se)
	}
	scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) { cb(null, { n: 1n }); }`)), KindError)
	scriptErr(t, must2(execLogin(t, r, `function login(e, p, cb) {`)), KindError)
}

func must2(_ json.RawMessage, err error) error { return err }

func TestRunnerFunctionForms(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	res, err := execLogin(t, r, `async function login(e, p, cb) { await Promise.resolve(); cb(null, { user_id: "a" }); }`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"a"}`)

	res, err = r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "get_user",
		Source: `function getByEmail(email, callback) { callback(null, { user_id: "g", email: email }); }`, Args: []any{"g@x.test"}})
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"g","email":"g@x.test"}`)

	res, err = execLogin(t, r, "// signs users in\nfunction login(e, p, cb) {\n  cb(null, { user_id: \"c\" });\n};\n")
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"c"}`)

	// Several top-level declarations: the runner falls back to the named function.
	res, err = execLogin(t, r, "function helper() { return \"h\"; }\nfunction login(e, p, cb) { cb(null, { user_id: helper() }); }")
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"h"}`)
}

func TestRunnerGlobalPersists(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	src := `function login(e, p, cb) { global.n = (global.n || 0) + 1; cb(null, { n: global.n }); }`
	for _, tc := range []struct {
		conn string
		want string
	}{{"c1", `{"n":1}`}, {"c1", `{"n":2}`}, {"c2", `{"n":1}`}} {
		res, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: tc.conn, Script: "login", Source: src, Args: []any{"e", "p"}})
		if err != nil {
			t.Fatal(err)
		}
		mustJSON(t, res, tc.want)
	}
}

func TestRunnerConfigIsolation(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	ctx := context.Background()
	read := `function login(e, p, cb) { cb(null, { k: configuration.K, frozen: Object.isFrozen(configuration) }); }`
	for _, tc := range []struct{ conn, k string }{{"c1", "one"}, {"c2", "two"}} {
		res, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: tc.conn, Script: "login", Source: read,
			Config: map[string]string{"K": tc.k}, Args: []any{"e", "p"}})
		if err != nil {
			t.Fatal(err)
		}
		mustJSON(t, res, fmt.Sprintf(`{"k":%q,"frozen":true}`, tc.k))
	}
	// Assignments are ignored (sloppy mode) or throw (strict mode); neither sticks.
	for _, src := range []string{
		`function login(e, p, cb) { configuration.K = "x"; configuration = { K: "y" }; cb(null, {}); }`,
		`function login(e, p, cb) { "use strict"; try { configuration = { K: "z" }; } catch (err) {} cb(null, {}); }`,
	} {
		if _, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Source: src,
			Config: map[string]string{"K": "one"}, Args: []any{"e", "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Source: read,
		Config: map[string]string{"K": "one"}, Args: []any{"e", "p"}})
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"k":"one","frozen":true}`)
}

func TestRunnerCallbackOnce(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	res, err := execLogin(t, r, `function login(e, p, cb) { cb(null, { v: 1 }); cb(null, { v: 2 }); }`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"v":1}`)
	res, err = execLogin(t, r, `function login(e, p, cb) { cb(null, { v: 3 }); throw new Error("after"); }`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"v":3}`)
}

func TestRunnerTimeoutKillsTenantProcess(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	ctx := context.Background()
	pidSrc := `function login(e, p, cb) { cb(null, { pid: process.pid }); }`
	pid := func(tenant string) float64 {
		t.Helper()
		res, err := r.Execute(ctx, Request{TenantID: tenant, ConnectionID: "c1", Script: "login", Source: pidSrc, Args: []any{"e", "p"}})
		if err != nil {
			t.Fatalf("%s: %v", tenant, err)
		}
		var out struct{ Pid float64 }
		if err := json.Unmarshal(res, &out); err != nil || out.Pid == 0 {
			t.Fatalf("%s: result %s", tenant, res)
		}
		return out.Pid
	}
	before := pid("t1")
	pid("t2") // warm t2 so the parallel call below does not pay for startup

	r.maxDuration = 300 * time.Millisecond
	var wg sync.WaitGroup
	var t2Err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		_, t2Err = r.Execute(ctx, Request{TenantID: "t2", ConnectionID: "c1", Script: "login", Source: pidSrc, Args: []any{"e", "p"}})
	}()
	start := time.Now()
	_, err := execLogin(t, r, `function login(e, p, cb) { while (true) {} }`)
	wg.Wait()
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("timeout took %v", d)
	}
	if t2Err != nil {
		t.Fatalf("parallel t2 call: %v", t2Err)
	}
	r.maxDuration = MaxDuration
	if after := pid("t1"); after == before {
		t.Fatalf("t1 still runs in pid %v after the timeout", before)
	}
}

func TestRunnerContextCancel(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Source: `function login(e, p, cb) { setTimeout(() => cb(null, { late: true }), 1000); }`, Args: []any{"e", "p"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	res, err := execLogin(t, r, `function login(e, p, cb) { cb(null, { ok: true }); }`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"ok":true}`)
}

func TestRunnerRequestValidation(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	_, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Args: []any{}})
	if !errors.Is(err, ErrNoScript) {
		t.Fatalf("empty source: %v", err)
	}
	_, err = r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "nope", Source: "function nope(){}"})
	if err == nil {
		t.Fatal("unknown script name accepted")
	}
}

func TestRunnerRequireAllowlist(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	res, err := execLogin(t, r, `function login(e, p, cb) {
	  cb(null, { h: require("crypto").createHash("sha256").update("x").digest("hex").slice(0, 8) });
	}`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"h":"2d711642"}`)
	for _, mod := range []string{"child_process", "node:worker_threads", "left-pad"} {
		_, err := execLogin(t, r, fmt.Sprintf(`function login(e, p, cb) { require(%q); cb(null, {}); }`, mod))
		scriptErr(t, err, KindError)
	}
}

func TestRunnerModulesDir(t *testing.T) {
	tmp := t.TempDir()
	pkg := filepath.Join(tmp, "node_modules", "zz-test")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "index.js"), []byte("module.exports = () => 7;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, config.CustomDB{ModulesDir: tmp})
	res, err := execLogin(t, r, `function login(e, p, cb) { cb(null, { n: require("zz-test")() }); }`)
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"n":7}`)
}

func TestRunnerFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"9"}`))
	}))
	defer srv.Close()
	r := newRunner(t, config.CustomDB{})
	res, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Source: `async function login(e, p, cb) {
		  const res = await fetch(configuration.URL, { signal: AbortSignal.timeout(5000) });
		  const body = await res.json();
		  cb(null, { user_id: body.id, ctl: typeof AbortController });
		}`,
		Config: map[string]string{"URL": srv.URL}, Args: []any{"e", "p"}})
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"9","ctl":"function"}`)
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRunnerConsoleLogged(t *testing.T) {
	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := newRunnerLog(t, config.CustomDB{}, log)
	_, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
		Source: `function login(e, p, cb) { console.log("hello", 1); cb(new Error("no")); }`,
		Args:   []any{"a@x.test", "pw-hunter2-secret"}})
	scriptErr(t, err, KindError)
	deadline := time.Now().Add(5 * time.Second)
	var line map[string]any
	for line == nil && time.Now().Before(deadline) {
		for _, l := range strings.Split(buf.String(), "\n") {
			if strings.Contains(l, "hello 1") {
				if err := json.Unmarshal([]byte(l), &line); err != nil {
					t.Fatal(err)
				}
			}
		}
		if line == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if line == nil {
		t.Fatalf("console output not logged; log:\n%s", buf.String())
	}
	if line["tenant"] != "t1" || line["connection"] != "c1" || line["output"] != "hello 1" || line["level"] != "INFO" {
		t.Fatalf("log record = %v", line)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("password leaked into logs:\n%s", buf.String())
	}
}

func TestRunnerIdleReaper(t *testing.T) {
	r := newRunner(t, config.CustomDB{IdleTimeout: 100 * time.Millisecond})
	if _, err := execLogin(t, r, `function login(e, p, cb) { cb(null, {}); }`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.procs)
		r.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle process not reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := execLogin(t, r, `function login(e, p, cb) { cb(null, {}); }`); err != nil {
		t.Fatalf("after reap: %v", err)
	}
}

const envProbe = `
	  const out = { env: JSON.stringify(process.env) };
	  const fs = require("fs");
	  for (const f of ["/proc/self/environ", "/proc/" + process.ppid + "/environ", "/etc/hostname"]) {
	    try { out[f] = fs.readFileSync(f, "utf8"); } catch (e) { out[f] = "denied:" + e.code; }
	  }
	  try {
	    out.cp = "ran:" + require("child_process").execFileSync("/bin/sh", ["-c", "echo $ZA_SENTINEL_SECRET"], { encoding: "utf8" });
	  } catch (e) { out.cp = "denied"; }
	  try { process.binding("spawn_sync"); out.binding = "loaded"; } catch (e) { out.binding = "denied"; }
`

func checkIsolated(t *testing.T, res json.RawMessage) map[string]any {
	t.Helper()
	t.Logf("isolation probe: %s", res)
	if bytes.Contains(res, []byte("sentinel-7f3a")) {
		t.Fatalf("host environment visible to the script: %s", res)
	}
	var got struct {
		AppMetadata map[string]any `json:"app_metadata"`
	}
	if err := json.Unmarshal(res, &got); err != nil {
		t.Fatal(err)
	}
	out := got.AppMetadata
	if out["env"] != "{}" {
		t.Errorf("process.env = %v, want {}", out["env"])
	}
	for k, v := range out {
		if !strings.HasPrefix(k, "/") {
			continue
		}
		if v != "denied:ERR_ACCESS_DENIED" && v != "" {
			t.Errorf("%s readable: %q", k, v)
		}
	}
	for _, f := range []string{"/proc/self/environ", "/etc/hostname"} {
		if _, ok := out[f]; !ok {
			t.Errorf("%s not probed", f)
		}
	}
	if out["cp"] != "denied" || out["binding"] != "denied" {
		t.Errorf("cp = %v, binding = %v; want denied", out["cp"], out["binding"])
	}
	return out
}

func TestRunnerCannotReadHostEnvironment(t *testing.T) {
	t.Setenv("ZA_SENTINEL_SECRET", "sentinel-7f3a")
	r := newRunner(t, config.CustomDB{})
	src := `function login(e, p, callback) {` + envProbe + `
	  callback(null, { user_id: "1", app_metadata: out });
	}`
	res, err := execLogin(t, r, src)
	if err != nil {
		t.Fatal(err)
	}
	checkIsolated(t, res)
}

func TestRunnerEscapedContextStillIsolated(t *testing.T) {
	t.Setenv("ZA_SENTINEL_SECRET", "sentinel-7f3a")
	r := newRunner(t, config.CustomDB{})
	// Reach the host realm's process through a constructor chain and use
	// process.getBuiltinModule, which skips the runner's require allowlist.
	// What still holds is the process boundary (empty env, --permission),
	// not vm; that boundary is what this test checks.
	src := `function login(e, p, callback) {
	  const process = this.constructor.constructor("return process")();
	  const require = process.getBuiltinModule;
	  const escaped = typeof process.pid === "number" && typeof require === "function";
	` + envProbe + `
	  out.escaped = escaped;
	  callback(null, { user_id: "1", app_metadata: out });
	}`
	res, err := execLogin(t, r, src)
	if err != nil {
		t.Fatal(err)
	}
	out := checkIsolated(t, res)
	if out["escaped"] != true {
		t.Fatalf("vm escape did not reach the host process: %v", out)
	}
}

func TestCheckNodeVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		"v22.13.0": true, "v22.23.3": true, "v23.0.0": true, "v26.8.1": true,
		"v22.12.9": false, "v20.18.0": false, "v18.0.0": false, "garbage": false, "": false,
	} {
		err := checkNodeVersion(v)
		if (err == nil) != ok {
			t.Errorf("checkNodeVersion(%q) = %v, want ok=%v", v, err, ok)
		}
		if err != nil && !errors.Is(err, ErrUnavailable) {
			t.Errorf("checkNodeVersion(%q) = %v, want ErrUnavailable", v, err)
		}
	}
}

func TestRunnerMissingNode(t *testing.T) {
	r, err := NewNodeRunner(config.CustomDB{Node: filepath.Join(t.TempDir(), "no-such-node")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = execLogin(t, r, `function login(e, p, cb) { cb(null, {}); }`)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestFuncExecutor(t *testing.T) {
	f := &FuncExecutor{Funcs: map[string]func([]any) (any, error){
		"login": func(args []any) (any, error) { return map[string]any{"user_id": args[0]}, nil },
	}}
	res, err := f.Execute(context.Background(), Request{Script: "login", Args: []any{"7"}})
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, res, `{"user_id":"7"}`)
	if _, err := f.Execute(context.Background(), Request{Script: "create"}); !errors.Is(err, ErrNoScript) {
		t.Fatalf("missing func: %v", err)
	}
	if n := len(f.Requests()); n != 2 {
		t.Fatalf("recorded %d calls, want 2", n)
	}
	var _ Executor = f
}

func TestRunnerUnprintableErrors(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	for _, src := range []string{
		`function login(e, p, cb) { cb(Object.create(null)); }`,
		`function login(e, p, cb) { const err = new Error("x"); Object.defineProperty(err, "message", { get() { throw new Error("no"); } }); cb(err); }`,
		`function login(e, p, cb) { throw Object.create(null); }`,
	} {
		start := time.Now()
		_, err := execLogin(t, r, src)
		scriptErr(t, err, KindError)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("took %v", d)
		}
	}
}

func TestRunnerTinyIdleTimeout(t *testing.T) {
	r := newRunner(t, config.CustomDB{IdleTimeout: time.Nanosecond})
	if _, err := execLogin(t, r, `function login(e, p, cb) { cb(null, {}); }`); err != nil {
		t.Fatal(err)
	}
}
