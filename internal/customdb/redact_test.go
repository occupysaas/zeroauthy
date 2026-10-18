package customdb

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestRedactorOverlapAndEmpty(t *testing.T) {
	d := NewRedactor(map[string]string{"a": "abc", "b": "abcdef", "c": "", "d": "zz"})
	if got, want := d.Redact("x abcdef y abc z zz"), "x "+Mask+" y "+Mask+" z "+Mask; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
	if got := d.Redact("ABC"); got != "ABC" {
		t.Errorf("case-insensitive match: %q", got)
	}
	if got := NewRedactor(map[string]string{"k": ""}).Redact("anything"); got != "anything" {
		t.Errorf("empty value masked: %q", got)
	}
	// Keys are not masked.
	if got := NewRedactor(map[string]string{"password": "pw"}).Redact("password"); got != "password" {
		t.Errorf("key masked: %q", got)
	}
}

func TestRedactorNoConfigPassesThrough(t *testing.T) {
	for _, d := range []*Redactor{nil, NewRedactor(nil), NewRedactor(map[string]string{})} {
		if got := d.Redact("s3cret"); got != "s3cret" {
			t.Errorf("Redact = %q", got)
		}
		raw := json.RawMessage(`{"b":1,  "a":"s3cret"}`)
		if got := d.RedactJSON(raw); string(got) != string(raw) {
			t.Errorf("RedactJSON = %s", got)
		}
	}
}

func TestRedactorJSON(t *testing.T) {
	d := NewRedactor(map[string]string{"k": "s3cret"})
	got := d.RedactJSON(json.RawMessage(`{"s3cret":1,"n":12345678901234567890,"o":{"x":"a s3cret b"},"l":["s3cret",2,null,true],"h":"<&>"}`))
	want := `{"h":"<&>","l":["` + Mask + `",2,null,true],"n":12345678901234567890,"o":{"x":"a ` + Mask + ` b"},"` + Mask + `":1}`
	if string(got) != want {
		t.Errorf("RedactJSON =\n%s\nwant\n%s", got, want)
	}
	if got := d.RedactJSON(json.RawMessage(`"s3cret"`)); string(got) != `"`+Mask+`"` {
		t.Errorf("top-level string = %s", got)
	}
}

const secret = "hunter2-s3cret"

func tryClient(t *testing.T, cfg map[string]string, fn func([]any) (any, error), logs []string) (*Client, *store.Connection) {
	t.Helper()
	c, fe, conn := clientFor(t, map[string]func([]any) (any, error){store.ScriptLogin: fn})
	fe.Logs = map[string][]string{store.ScriptLogin: logs}
	sealed, err := keys.SealConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.ConfigurationSealed = sealed
	return c, conn
}

func TestTryMasksConfigurationValues(t *testing.T) {
	cfg := map[string]string{"dbPassword": secret, "abc": "abc", "long": "abcdef", "empty": ""}
	c, conn := tryClient(t, cfg, func([]any) (any, error) {
		return map[string]any{
			"top": secret, "nested": map[string]any{"deep": "pre-" + secret + "-post"},
			secret: "as key", "arr": []any{secret, 1},
		}, nil
	}, []string{"connecting with " + secret, "plain", "abcdef and abc"})
	var logs []string
	raw, err := c.Try(context.Background(), conn, store.ScriptLogin, []any{"a", "b"}, func(l []string) { logs = l })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || !strings.Contains(string(raw), Mask) {
		t.Errorf("result = %s", raw)
	}
	var res struct {
		Top    string
		Nested map[string]string
		Arr    []any
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.Top != Mask || res.Nested["deep"] != "pre-"+Mask+"-post" || res.Arr[0] != Mask {
		t.Errorf("result = %s", raw)
	}
	if !strings.Contains(string(raw), `"`+Mask+`":"as key"`) {
		t.Errorf("object key not masked: %s", raw)
	}
	if len(logs) != 3 || logs[0] != "connecting with "+Mask || logs[1] != "plain" || logs[2] != Mask+" and "+Mask {
		t.Errorf("logs = %q", logs)
	}
}

func TestTryMasksTopLevelStringAndError(t *testing.T) {
	c, conn := tryClient(t, map[string]string{"k": secret}, func([]any) (any, error) { return secret, nil }, nil)
	raw, err := c.Try(context.Background(), conn, store.ScriptLogin, []any{"a", "b"}, nil)
	if err != nil || string(raw) != `"`+Mask+`"` {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
	c, conn = tryClient(t, map[string]string{"k": secret}, func([]any) (any, error) {
		return nil, &ScriptError{Kind: KindError, Code: "c-" + secret, Message: "cannot reach db with " + secret}
	}, nil)
	_, err = c.Try(context.Background(), conn, store.ScriptLogin, []any{"a", "b"}, nil)
	se := scriptErr(t, err, KindError)
	if se.Message != "cannot reach db with "+Mask || se.Code != "c-"+secret {
		t.Errorf("error = %+v", se)
	}
}

func TestTryWithoutConfigurationUnchanged(t *testing.T) {
	c, conn := tryClient(t, nil, func([]any) (any, error) { return map[string]any{"z": secret, "a": 1}, nil }, []string{secret})
	var logs []string
	raw, err := c.Try(context.Background(), conn, store.ScriptLogin, []any{"a", "b"}, func(l []string) { logs = l })
	if err != nil || string(raw) != `{"a":1,"z":"`+secret+`"}` || len(logs) != 1 || logs[0] != secret {
		t.Fatalf("raw = %s, logs = %q, err = %v", raw, logs, err)
	}
}

// waitLog polls buf until it contains want.
func waitLog(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q:\n%s", want, buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServerLogMasksConfigurationValues(t *testing.T) {
	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := newRunnerLog(t, config.CustomDB{}, log)
	c := &Client{Exec: r, Wrapper: testWrapper(t)}
	conn := &store.Connection{TenantID: "ten_a", ID: "con_1", Name: "Legacy", Strategy: store.StrategyDatabase,
		EnabledDatabaseCustomization: true, CustomScripts: map[string]string{
			store.ScriptLogin: `function login(e, p, cb) { console.log("marker-login", configuration.dbPassword); cb(null, {user_id: "1", email: e}); }`,
		}}
	sealed, err := keys.SealConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, map[string]string{"dbPassword": secret})
	if err != nil {
		t.Fatal(err)
	}
	conn.ConfigurationSealed = sealed

	// A real login.
	if _, err := c.Login(context.Background(), conn, "a@x.test", "pw"); err != nil {
		t.Fatal(err)
	}
	waitLog(t, &buf, "marker-login")
	// A try, which also captures the lines for its response.
	var logs []string
	if _, err := c.Try(context.Background(), conn, store.ScriptLogin, []any{"a@x.test", "pw"}, func(l []string) { logs = l }); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0] != "marker-login "+Mask {
		t.Errorf("logs = %q", logs)
	}
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(buf.String(), "marker-login") < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "marker-login") != 2 || !strings.Contains(out, "marker-login "+Mask) {
		t.Errorf("log lines missing:\n%s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked into the server log:\n%s", out)
	}
}

func TestLoginErrorUnmodified(t *testing.T) {
	c, conn := tryClient(t, map[string]string{"k": secret}, func([]any) (any, error) {
		return nil, &ScriptError{Kind: KindError, Message: "bad " + secret}
	}, nil)
	_, err := c.Login(context.Background(), conn, "a", "b")
	// Login returns the script's error as it is; callers mask what they log.
	if se := scriptErr(t, err, KindError); se.Message != "bad "+secret {
		t.Errorf("error = %v", err)
	}
}

func TestRedactLineMasksValuePrefixAtCut(t *testing.T) {
	d := NewRedactor(map[string]string{"k": "hunter2-s3cret"})
	long := strings.Repeat("x", 2048-5)
	if got, want := d.RedactLine(long+"hunte"), long+Mask; got != want {
		t.Errorf("cut prefix not masked: ...%q", got[len(got)-12:])
	}
	if got := d.RedactLine("short line h"); got != "short line h" {
		t.Errorf("short line changed: %q", got)
	}
	if got := d.RedactLine(long + "hunte!"); got != long+"hunte!" {
		t.Errorf("non-suffix changed")
	}
}

func TestServerLogMasksSecretAtTruncation(t *testing.T) {
	var buf syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&buf, nil)))
	c := &Client{Exec: r, Wrapper: testWrapper(t)}
	conn := &store.Connection{TenantID: "ten_a", ID: "con_1", Name: "L", Strategy: store.StrategyDatabase,
		CustomScripts: map[string]string{store.ScriptLogin: `function login(e, p, cb) {
			console.log("x".repeat(2040) + configuration.dbPassword);
			cb(null, {user_id: "1", email: e}); }`}}
	conn.ConfigurationSealed, _ = keys.SealConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, map[string]string{"dbPassword": secret})
	var logs []string
	if _, err := c.Try(context.Background(), conn, store.ScriptLogin, []any{"a@x.test", "pw"}, func(l []string) { logs = l }); err != nil {
		t.Fatal(err)
	}
	waitLog(t, &buf, "custom database script")
	time.Sleep(100 * time.Millisecond)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || !strings.HasSuffix(logs[0], Mask) || strings.Contains(logs[0], "hunter") {
		t.Errorf("captured line ends %q", logs[0][len(logs[0])-20:])
	}
	if out := buf.String(); strings.Contains(out, "hunter") || !strings.Contains(out, "■") {
		t.Errorf("server log:\n%s", out)
	}
}

func TestServerLogMasksOldValueAfterRotation(t *testing.T) {
	var buf syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&buf, nil)))
	// The script logs the old value late, after the configuration changed.
	src := `function login(e, p, cb) {
		const old = globalThis.__old ??= "OLDVAL-" + "s3cret";
		if (p === "first") { cb(null, {user_id: "1", email: e}); }
		else { cb(null, {user_id: "1", email: e}); setTimeout(() => console.log("late", old), 200); }
	}`
	run := func(cfg map[string]string, pw string) {
		if _, err := r.Execute(context.Background(), Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Source: src,
			Config: cfg, Args: []any{"a", pw}}); err != nil {
			t.Fatal(err)
		}
	}
	run(map[string]string{"k": "OLDVAL-s3cret"}, "first")
	run(map[string]string{"k": "newval"}, "second")
	waitLog(t, &buf, "late")
	if out := buf.String(); strings.Contains(out, "OLDVAL") || !strings.Contains(out, "late "+Mask) {
		t.Errorf("server log:\n%s", out)
	}
	// A line with no connection (an uncaught error) is masked with every value seen.
	if got := (&proc{all: NewRedactor(map[string]string{"a": "one"}).Union(NewRedactor(map[string]string{"b": "two"}))}).redactorFor("").Redact("one two"); got != Mask+" "+Mask {
		t.Errorf("union = %q", got)
	}
}
