package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// lockedBuffer is a log sink safe for concurrent handlers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

const secretMarker = "zz-never-logged"

type scriptEnv struct {
	t     *testing.T
	h     http.Handler
	st    store.Store
	exec  *customdb.FuncExecutor
	log   *lockedBuffer
	op    string
	opID  string
	conn  string // a connection with every script, customization off
	other string // a connection with only a login script
}

func newScriptEnv(t *testing.T) *scriptEnv {
	t.Helper()
	e := &scriptEnv{t: t, log: &lockedBuffer{}}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	e.exec = &customdb.FuncExecutor{Funcs: map[string]func([]any) (any, error){}, Logs: map[string][]string{}}
	e.h, e.st = newMgmtEnvWith(t, func(d *Deps) {
		d.Scripts = &customdb.Client{Exec: e.exec, Wrapper: w}
		d.Log = slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	e.op, e.opID = operatorToken(t, e.st, "op@example.test")
	tn, err := e.st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, name string, scripts map[string]string, custom bool) {
		sealed, err := keys.SealConnectionConfig(w, tn.ID, id, map[string]string{"dbpass": secretMarker + "-config"})
		if err != nil {
			t.Fatal(err)
		}
		c := &store.Connection{
			ID: id, TenantID: tn.ID, Name: name, Strategy: store.StrategyDatabase,
			EnabledDatabaseCustomization: custom, CustomScripts: scripts, ConfigurationSealed: sealed,
		}
		if err := e.st.Connections().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	all := map[string]string{}
	for _, n := range store.ScriptNames {
		all[n] = "function(){}"
	}
	mk("con_TryAll", "try-all", all, false) // customization off: still testable
	mk("con_TryOne", "try-one", map[string]string{"login": "function(){}"}, true)
	e.conn, e.other = "con_TryAll", "con_TryOne"
	return e
}

func (e *scriptEnv) url(tenant, conn, script string) string {
	return fmt.Sprintf("https://%s/api/system/tenants/%s/connections/%s/scripts/%s/try", mgmtSystemHost, tenant, conn, script)
}

func (e *scriptEnv) try(conn, script string, body any) (int, map[string]any) {
	e.t.Helper()
	rec, out := sendRaw(e.h, "POST", e.url("acme", conn, script), e.op, body)
	m, _ := out.(map[string]any)
	return rec.Code, m
}

func TestTryScriptEachName(t *testing.T) {
	counts := map[string][]any{
		"login":           {"a@b.test", "pw"},
		"get_user":        {"a@b.test"},
		"create":          {map[string]any{"email": "a@b.test", "password": "pw"}},
		"verify":          {"a@b.test"},
		"change_password": {"a@b.test", "newpw"},
		"delete":          {"auth0-id"},
		"change_email":    {"a@b.test", "c@d.test", true},
	}
	if len(counts) != len(store.ScriptNames) {
		t.Fatalf("test covers %d scripts, store has %d", len(counts), len(store.ScriptNames))
	}
	for script, args := range counts {
		t.Run(script, func(t *testing.T) {
			e := newScriptEnv(t)
			e.exec.Funcs[script] = func(got []any) (any, error) { return map[string]any{"ran": script, "n": len(got)}, nil }
			e.exec.Logs[script] = []string{"hello", "warn: careful"}
			status, out := e.try(e.conn, script, map[string]any{"args": args})
			if status != 200 {
				t.Fatalf("status %d %v", status, out)
			}
			res, _ := out["result"].(map[string]any)
			if res["ran"] != script || res["n"] != float64(len(args)) {
				t.Errorf("result = %v", out["result"])
			}
			if out["error"] != nil {
				t.Errorf("error = %v", out["error"])
			}
			if logs, _ := out["logs"].([]any); len(logs) != 2 || logs[0] != "hello" {
				t.Errorf("logs = %v", out["logs"])
			}
			if _, ok := out["duration_ms"].(float64); !ok {
				t.Errorf("duration_ms = %v", out["duration_ms"])
			}
			calls := e.exec.Requests()
			if len(calls) != 1 || calls[0].Script != script || len(calls[0].Args) != len(args) || calls[0].ConnectionID != e.conn ||
				calls[0].Config["dbpass"] != secretMarker+"-config" {
				t.Errorf("request = %+v", calls)
			}
		})
	}
}

func TestTryScriptNullResultAndEmptyLogs(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, nil }
	status, out := e.try(e.conn, "get_user", map[string]any{"args": []any{"x@y.test"}})
	logs, isList := out["logs"].([]any)
	if status != 200 || out["result"] != nil || out["error"] != nil || !isList || len(logs) != 0 {
		t.Errorf("%d %v", status, out)
	}
}

func TestTryScriptErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err           error
		wantName, msg string
	}{
		"thrown":     {&customdb.ScriptError{Kind: customdb.KindError, Message: "boom"}, "Error", "boom"},
		"validation": {&customdb.ScriptError{Kind: customdb.KindValidation, Code: "x", Message: "bad"}, "ValidationError", "bad"},
		"wrong":      {&customdb.ScriptError{Kind: customdb.KindWrongCredentials, Message: "nope"}, "WrongUsernameOrPasswordError", "nope"},
		"unauth":     {&customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "no"}, "UnauthorizedError", "no"},
		"timeout":    {customdb.ErrTimeout, "TimeoutError", ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newScriptEnv(t)
			e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, tc.err }
			status, out := e.try(e.conn, "get_user", map[string]any{"args": []any{"x@y.test"}})
			er, _ := out["error"].(map[string]any)
			if status != 200 || er["name"] != tc.wantName || out["result"] != nil {
				t.Fatalf("%d %v", status, out)
			}
			if tc.msg != "" && er["message"] != tc.msg {
				t.Errorf("message = %v", er["message"])
			}
			if er["message"] == "" || er["message"] == nil {
				t.Errorf("message empty: %v", er)
			}
		})
	}
}

func TestTryScriptRuntimeUnavailable(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, fmt.Errorf("%w: node missing", customdb.ErrUnavailable) }
	status, out := e.try(e.conn, "get_user", map[string]any{"args": []any{"x"}})
	if status != 503 || errCode(out) != "script_runtime_unavailable" || out["statusCode"] != float64(503) {
		t.Errorf("%d %v", status, out)
	}
	e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, errors.New("weird") }
	if status, out = e.try(e.conn, "get_user", map[string]any{"args": []any{"x"}}); status != 500 {
		t.Errorf("unexpected error = %d %v", status, out)
	}
}

func TestTryScriptNoClient(t *testing.T) {
	h, st := newMgmtEnv(t) // no Scripts
	op, _ := operatorToken(t, st, "op@example.test")
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	if err := st.Connections().Create(context.Background(), &store.Connection{
		ID: "con_NoClient", TenantID: tn.ID, Name: "nc", Strategy: store.StrategyDatabase, CustomScripts: map[string]string{"login": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	rec, out := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/connections/con_NoClient/scripts/login/try", op, map[string]any{"args": []any{"a", "b"}})
	if rec.Code != 503 || errCode(out) != "script_runtime_unavailable" {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestTryScriptValidation(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["login"] = func([]any) (any, error) { return map[string]any{}, nil }
	for name, tc := range map[string]struct {
		conn, script string
		body         any
		status       int
		code         string
	}{
		"too few":        {e.conn, "login", map[string]any{"args": []any{"a"}}, 400, "invalid_body"},
		"too many":       {e.conn, "login", map[string]any{"args": []any{"a", "b", "c"}}, 400, "invalid_body"},
		"no args":        {e.conn, "login", map[string]any{}, 400, "invalid_body"},
		"null args":      {e.conn, "login", map[string]any{"args": nil}, 400, "invalid_body"},
		"args not list":  {e.conn, "login", map[string]any{"args": "a"}, 400, "invalid_body"},
		"extra property": {e.conn, "login", map[string]any{"args": []any{"a", "b"}, "x": 1}, 400, "invalid_body"},
		"not an object":  {e.conn, "login", []any{"a", "b"}, 400, "invalid_body"},
		"unknown script": {e.conn, "frobnicate", map[string]any{"args": []any{}}, 400, "invalid_body"},
		"no source":      {e.other, "get_user", map[string]any{"args": []any{"a"}}, 400, "invalid_body"},
		"unknown conn":   {"con_Missing", "login", map[string]any{"args": []any{"a", "b"}}, 404, "inexistent_connection"},
		"malformed id":   {"not-an-id", "login", map[string]any{"args": []any{"a", "b"}}, 400, "invalid_uri"},
	} {
		status, out := e.try(tc.conn, tc.script, tc.body)
		if status != tc.status || errCode(out) != tc.code {
			t.Errorf("%s: %d %v, want %d %s", name, status, out, tc.status, tc.code)
		}
	}
	if _, m := e.try(e.other, "get_user", map[string]any{"args": []any{"a"}}); !strings.Contains(fmt.Sprint(m["message"]), "no get_user script") {
		t.Errorf("missing source message = %v", m["message"])
	}
	rec, out := sendRaw(e.h, "POST", e.url("nosuch", e.conn, "login"), e.op, map[string]any{"args": []any{"a", "b"}})
	if rec.Code != 404 || errCode(out) != "inexistent_tenant" {
		t.Errorf("unknown tenant = %d %s", rec.Code, rec.Body)
	}
	if n := len(e.exec.Requests()); n != 0 {
		t.Errorf("runner called %d times for refused requests", n)
	}
}

func TestTryScriptAuth(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, nil }
	body := map[string]any{"args": []any{"a"}}
	admin := clientToken(t, e.h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for name, tc := range map[string]struct {
		url, token string
		status     int
	}{
		"no token":        {e.url("acme", e.conn, "get_user"), "", 401},
		"M2M token":       {e.url("acme", e.conn, "get_user"), admin, 401},
		"tenant host":     {fmt.Sprintf("https://acme.example.test/api/system/tenants/acme/connections/%s/scripts/get_user/try", e.conn), e.op, 404},
		"tenant host M2M": {fmt.Sprintf("https://acme.example.test/api/system/tenants/acme/connections/%s/scripts/get_user/try", e.conn), admin, 404},
	} {
		rec, _ := sendRaw(e.h, "POST", tc.url, tc.token, body)
		if rec.Code != tc.status {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body, tc.status)
		}
	}
	if n := len(e.exec.Requests()); n != 0 {
		t.Errorf("runner called %d times for refused callers", n)
	}
}

func TestTryScriptRateLimit(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["get_user"] = func([]any) (any, error) { return nil, nil }
	body := map[string]any{"args": []any{"a"}}
	for i := 1; i <= 10; i++ {
		if status, out := e.try(e.conn, "get_user", body); status != 200 {
			t.Fatalf("call %d = %d %v", i, status, out)
		}
	}
	rec, out := sendRaw(e.h, "POST", e.url("acme", e.conn, "get_user"), e.op, body)
	if rec.Code != 429 || errCode(out) != "too_many_requests" || rec.Header().Get("Retry-After") == "" {
		t.Errorf("11th = %d %s retry-after %q", rec.Code, rec.Body, rec.Header().Get("Retry-After"))
	}
	// Another operator has their own allowance.
	op2, _ := operatorToken(t, e.st, "op2@example.test")
	if rec, _ := sendRaw(e.h, "POST", e.url("acme", e.conn, "get_user"), op2, body); rec.Code != 200 {
		t.Errorf("second operator = %d %s", rec.Code, rec.Body)
	}
	if n := len(e.exec.Requests()); n != 11 {
		t.Errorf("runner calls = %d, want 11", n)
	}
}

func TestTryScriptLogLine(t *testing.T) {
	e := newScriptEnv(t)
	e.exec.Funcs["login"] = func([]any) (any, error) { return map[string]any{"user_id": secretMarker + "-result"}, nil }
	e.exec.Logs["login"] = []string{secretMarker + "-console"}
	status, out := e.try(e.conn, "login", map[string]any{"args": []any{secretMarker + "-user@x.test", secretMarker + "-password"}})
	if status != 200 {
		t.Fatalf("%d %v", status, out)
	}
	e.exec.Funcs["login"] = func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: secretMarker + "-errmsg"}
	}
	if status, _ = e.try(e.conn, "login", map[string]any{"args": []any{secretMarker + "-user@x.test", secretMarker + "-password"}}); status != 200 {
		t.Fatal(status)
	}
	logged := e.log.String()
	if strings.Contains(logged, secretMarker) {
		t.Errorf("the log holds arguments, results, console output, errors or configuration:\n%s", logged)
	}
	lines := 0
	for _, l := range strings.Split(logged, "\n") {
		if !strings.Contains(l, "try custom database script") {
			continue
		}
		lines++
		for _, want := range []string{"tenant=acme", "connection=con_TryAll", "script=login", "operator=" + e.opID, "duration_ms=", "outcome="} {
			if !strings.Contains(l, want) {
				t.Errorf("log line lacks %q: %s", want, l)
			}
		}
	}
	if lines != 2 {
		t.Errorf("%d log lines, want 2:\n%s", lines, logged)
	}
	if !strings.Contains(logged, "outcome=ok") || !strings.Contains(logged, "outcome=script_error") {
		t.Errorf("outcomes missing:\n%s", logged)
	}
}
