package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestActionConsoleCaptured(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "console", `exports.onExecutePostLogin=(event,api)=>{console.log(event.secrets.KEY,'request-password','a'); console.log(JSON.stringify({password:'unregistered',normal:'request-password'}));for(let i=0;i<90;i++)console.log('x'.repeat(2000));};`, map[string]string{"KEY": "abc"}, false)
	h.bind("t1", trigLogin, a)
	ctx := logscrub.WithCredentials(context.Background(), "request-password", "a")
	in := h.loginInput("t1")
	out, err := h.eng.PostLogin(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	ex := h.execution("t1", out.ExecutionID)
	lines := ex.Results[0].Logs
	joined := strings.Join(lines, "\n")
	if len(lines) == 0 || strings.Contains(joined, "request-password") || strings.Contains(joined, "abc") || strings.Contains(joined, "unregistered") {
		t.Fatalf("unsafe console: %q", joined[:min(len(joined), 300)])
	}
	if len(joined) > 64*1024 || lines[len(lines)-1] != "… truncated" {
		t.Fatalf("cap bytes=%d tail=%q", len(joined), lines[len(lines)-1])
	}
	lines[0] = "mutated"
	if h.execution("t1", out.ExecutionID).Results[0].Logs[0] == "mutated" {
		t.Fatal("mutable read")
	}
}

type actionOutcomeRecorder struct{ events chan logs.Event }

func (r *actionOutcomeRecorder) Record(_ context.Context, e logs.Event) { r.events <- e }
func TestAsyncJobFailureLogged(t *testing.T) {
	for _, tr := range []string{actions.TriggerPostChangePassword, actions.TriggerPostUserRegistration, actions.TriggerCustomEmailProvider} {
		t.Run(tr, func(t *testing.T) {
			h := newHarness(t)
			handler := "onExecutePostChangePassword"
			if tr == actions.TriggerPostUserRegistration {
				handler = "onExecutePostUserRegistration"
			}
			if tr == actions.TriggerCustomEmailProvider {
				handler = "onExecuteCustomEmailProvider"
			}
			a := h.action("t1", tr, "fails", `exports.`+handler+`=()=>{throw Error('private failure')};`, nil, false)
			h.bind("t1", tr, a)
			enqueueJob(t, h, tr, map[string]any{"user": map[string]any{"user_id": "auth0|u1"}})
			capture := &actionOutcomeRecorder{events: make(chan logs.Event, 10)}
			h.eng.Recorder = capture
			h.eng.Now = func() time.Time { h.advance(10 * time.Minute); return h.clock() }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				(&actions.Worker{Engine: h.eng, Store: h.st, Workers: 1, Poll: time.Millisecond, Lease: time.Hour}).Run(ctx)
			}()
			defer func() { cancel(); <-done }()
			select {
			case event := <-capture.events:
				if event.Type != "actions_execution_failed" || event.TenantID != "t1" || len(event.ExecutionIDs) == 0 || strings.Contains(event.Description, "private") {
					t.Fatalf("event=%+v", event)
				}
				if tr == actions.TriggerCustomEmailProvider && len(event.ExecutionIDs) != 6 {
					t.Fatalf("attempts=%+v", event)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no terminal failure event")
			}
			cancel()
			<-done
			select {
			case extra := <-capture.events:
				t.Fatalf("duplicate terminal event=%+v", extra)
			default:
			}
		})
	}
}

func TestActionConsoleEscapedScalarCredential(t *testing.T) {
	for _, password := range []string{"line\nbreak\"value", `"quoted-secret"`, `{"value":"json-secret"}`, `{ "value" : "json-secret" }`, `"\u0071uoted-secret"`, `{ "password" : "hidden", "value":"json-secret" }`} {
		t.Run(password, func(t *testing.T) {
			h := newHarness(t)
			encoded, _ := json.Marshal(password)
			a := h.action("t1", trigLogin, "escaped", `exports.onExecutePostLogin=()=>{const p=`+string(encoded)+`;console.log(p);console.log(JSON.stringify(p));};`, nil, false)
			h.bind("t1", trigLogin, a)
			out, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), password), h.loginInput("t1"))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range h.execution("t1", out.ExecutionID).Results[0].Logs {
				if strings.Contains(line, "line") || strings.Contains(line, "secret") || !strings.Contains(line, logscrub.Marker) {
					t.Fatalf("escaped credential leaked: %q", line)
				}
			}
		})
	}
}

func TestActionConsoleCredentialBoundaries(t *testing.T) {
	for _, password := range []string{"a", "bc", "猫", "prefix-middle-suffix"} {
		t.Run(password, func(t *testing.T) {
			h := newHarness(t)
			encoded, _ := json.Marshal(password)
			a := h.action("t1", trigLogin, "privacy", `exports.onExecutePostLogin=(e)=>{const p=`+string(encoded)+`;console.log(p);console.log(JSON.stringify({[p]:p,password:'unknown credential'}));console.log('x'.repeat(2040)+p);console.log(e.secrets.KEY);};`, map[string]string{"KEY": "middle"}, false)
			h.bind("t1", trigLogin, a)
			out, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), password), h.loginInput("t1"))
			if err != nil {
				t.Fatal(err)
			}
			lines := h.execution("t1", out.ExecutionID).Results[0].Logs
			if lines[0] != logscrub.Marker || strings.Contains(lines[1], "unknown credential") || strings.Contains(lines[1], password) {
				t.Fatalf("unsafe credential console: %q", lines)
			}
			if password == "prefix-middle-suffix" && lines[2] != strings.Repeat("x", 2040)+logscrub.Marker {
				t.Fatalf("truncated credential prefix leaked: %q", lines[2])
			}
			if lines[3] != "■■■■■■■■" {
				t.Fatalf("config mask=%q", lines[3])
			}
		})
	}
}

type finishFailureStore struct {
	store.Store
	called chan struct{}
}

func (s finishFailureStore) Actions() store.Actions {
	return finishFailureActions{s.Store.Actions(), s.called}
}

type finishFailureActions struct {
	store.Actions
	called chan struct{}
}

func (a finishFailureActions) FinishJob(context.Context, *store.ActionJob, time.Time) error {
	close(a.called)
	return errors.New("finish rolled back")
}
func TestAsyncJobFailureNotLoggedWhenFinishRollsBack(t *testing.T) {
	h := newHarness(t)
	tr := actions.TriggerPostChangePassword
	a := h.action("t1", tr, "fails", `exports.onExecutePostChangePassword=()=>{throw Error('failure')};`, nil, false)
	h.bind("t1", tr, a)
	enqueueJob(t, h, tr, map[string]any{})
	capture := &actionOutcomeRecorder{events: make(chan logs.Event, 10)}
	h.eng.Recorder = capture
	called := make(chan struct{})
	wrapped := finishFailureStore{h.st, called}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&actions.Worker{Engine: h.eng, Store: wrapped, Workers: 1, Poll: time.Millisecond, Lease: time.Hour}).Run(ctx)
	}()
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("finish was not attempted")
	}
	cancel()
	<-done
	select {
	case e := <-capture.events:
		t.Fatalf("event on rollback=%+v", e)
	default:
	}
}

func TestActionConsoleShortCredentialPreservesDenyCode(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigM2M, "deny", `exports.onExecuteCredentialsExchange=(e,api)=>{api.access.deny('invalid_request','credential a');};`, nil, false)
	h.bind("t1", trigM2M, a)
	out, err := h.eng.CredentialsExchange(logscrub.WithCredentials(context.Background(), "a"), h.m2mInput("t1"))
	if err != nil || out.Denied == nil || out.Denied.Code != "invalid_request" || strings.Contains(out.Denied.Reason, "a") {
		t.Fatalf("denial=%+v err=%v", out, err)
	}
}

// Exercise the real Node formatter and both operator console responses. Redaction
// must precede severity prefixes, argument joining and the runner's line cutoff.
func TestActionConsolePrivacyBeforeFormatting(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"warn_object", `console.warn({password:'unregistered-private-value'});`},
		{"error_nested", `console.error({normal:[{nested:{'API.-KEY':'unregistered-private-value'}}]});`},
		{"oversized_object", `console.log({password:'unregistered-private-value',padding:'x'.repeat(3000)});`},
		{"encoded_nested", `console.debug('prefix',JSON.stringify({normal:JSON.stringify([{password:'unregistered-private-value'}])}));`},
		{"immutable", `const v={password:'unregistered-private-value'};console.warn(v);if(v.password!=='unregistered-private-value')throw Error('console mutated script data');`},
		{"cycle", `const v={password:'unregistered-private-value'};v.self=v;console.warn(v);`},
		{"deep", `let v={password:'unregistered-private-value'};for(let i=0;i<100;i++)v={normal:v};console.warn(v);`},
		{"toJSON", `console.warn({password:'unregistered-private-value',toJSON(){return this.password}});`},
		{"key_policy", `console.warn(Object.fromEntries(['Password','pre-PASSWD-post','p.w.d','client-secret','refresh_token','Authorization','API.-KEY','private_key','Credential','OTP','recovery-code','prİvatekey'].map(k=>[k,'unregistered-private-value'])));`},
		{"wide", `console.warn(Object.fromEntries(Array.from({length:9000},(_,i)=>['key'+i,{password:'unregistered-private-value'}])));`},
		{"sparse_array", `const v=[];v[1000000]={password:'unregistered-private-value'};console.warn(v);`},
		{"accessor", `console.warn({get value(){return 'unregistered-private-value'}});`},
		{"escaped_cut", `console.log('x'.repeat(2035)+JSON.stringify(p));`},
		{"escaped_prefix", `console.error('prefix',JSON.stringify(p));`},
		{"escaped_configuration_cut", `console.warn('x'.repeat(2035)+JSON.stringify(e.secrets.KEY));`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			password := "line\nbreak\"value"
			encoded, _ := json.Marshal(password)
			var configuration map[string]string
			if tc.name == "escaped_configuration_cut" {
				configuration = map[string]string{"KEY": password}
			}
			a := h.action("t1", trigLogin, "privacy", `exports.onExecutePostLogin=(e)=>{const p=`+string(encoded)+`;`+tc.body+`};`, configuration, false)
			h.bind("t1", trigLogin, a)
			out, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), password), h.loginInput("t1"))
			if err != nil {
				t.Fatal(err)
			}
			ex := h.execution("t1", out.ExecutionID)
			check := func(where string, lines []string) {
				t.Helper()
				if len(lines) != 1 {
					t.Fatalf("%s logs=%q", where, lines)
				}
				line := lines[0]
				for _, secret := range []string{"unregistered-private-value", "line", `line\n`, "break", password} {
					if strings.Contains(line, secret) {
						t.Errorf("%s leaked %q in %q", where, secret, line)
					}
				}
				if !strings.Contains(line, logscrub.Marker) && !strings.Contains(line, "■■■■■■■■") {
					t.Errorf("%s missing redaction: %q", where, line)
				}
			}
			check("persisted", ex.Results[0].Logs)
			handlers := &mgmt.Handlers{Store: h.st}
			for _, list := range []bool{false, true} {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "https://system.example/api/system/tenants/t1/actions/executions", nil)
				if list {
					handlers.GetTenantActionExecutions(rec, req, "t1", mgmtapi.GetTenantActionExecutionsParams{})
				} else {
					handlers.GetTenantActionExecution(rec, req, "t1", out.ExecutionID)
				}
				var doc struct {
					Results []struct {
						Logs []string `json:"logs"`
					} `json:"results"`
				}
				if rec.Code != 200 {
					t.Fatalf("system response %d %s", rec.Code, rec.Body)
				}
				if list {
					var docs []json.RawMessage
					if err := json.Unmarshal(rec.Body.Bytes(), &docs); err != nil || len(docs) != 1 {
						t.Fatalf("list %s: %v", rec.Body, err)
					}
					if err := json.Unmarshal(docs[0], &doc); err != nil {
						t.Fatal(err)
					}
				} else if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Results) != 1 {
					t.Fatalf("system response %s", rec.Body)
				}
				check("system response", doc.Results[0].Logs)
			}
		})
	}
}

func TestActionConsoleEscapedCredentialStderr(t *testing.T) {
	h := newHarness(t)
	password := "line\nbreak\"value"
	encoded, _ := json.Marshal(password)
	a := h.action("t1", trigLogin, "stderr", `exports.onExecutePostLogin=()=>{const p=`+string(encoded)+`;setTimeout(()=>{throw Error('x'.repeat(1011)+JSON.stringify(p))},10)};`, nil, false)
	h.bind("t1", trigLogin, a)
	if _, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), password), h.loginInput("t1")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(h.logs.String(), "uncaught:") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	output := h.logs.String()
	if !strings.Contains(output, "uncaught:") || !strings.Contains(output, "■■■■■■■■") {
		t.Fatalf("missing stderr redaction: %s", output)
	}
	for _, secret := range []string{"line", "break", password} {
		if strings.Contains(output, secret) {
			t.Errorf("stderr leaked %q: %s", secret, output)
		}
	}
}

// Missing denial metadata must fail without converting a normal deny to an error.
func TestActionExecutionDenialReason(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		failure          bool
	}{
		{"deny", `api.access.deny('Blocked by policy')`, "Blocked by policy", false},
		{"request short", `api.access.deny('z')`, "[REDACTED]", false},
		{"bounded", `api.access.deny('X'.repeat(600))`, strings.Repeat("X", 512), false},
		{"nested secret", `api.access.deny(JSON.stringify({password:'unknown'}))`, `{"password":"[REDACTED]"}`, false},
		{"short and overlap", `api.access.deny('q prefix-middle-suffix')`, "■■■■■■■■ [REDACTED]", false},
		{"before bound", `api.access.deny('X'.repeat(500)+'prefix-middle-suffix')`, strings.Repeat("X", 500) + "[REDACTED]", false},
		{"throw", `throw Error('failure')`, "", true},
		{"deny then throw", `api.access.deny('must not persist'); throw Error('failure')`, "", true},
		{"success", ``, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			m, v := moduleFixture(t, h, "t1", "mask", `exports.noop=()=>{};`, map[string]string{"KEY": "middle"})
			a := h.action("t1", trigLogin, "denier", `exports.onExecutePostLogin=(event,api)=>{`+tc.body+`};`, map[string]string{"SHORT": "q"}, false)
			pinModule(t, h, a, m, v)
			h.bind("t1", trigLogin, a)
			out, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), "prefix-middle-suffix", "z"), h.loginInput("t1"))
			id := ""
			if tc.failure {
				var fe *actions.ErrFlow
				if !errors.As(err, &fe) {
					t.Fatalf("expected runtime error: %v", err)
				}
				id = fe.ExecutionID
			} else {
				if err != nil {
					t.Fatal(err)
				}
				id = out.ExecutionID
			}
			ex := h.execution("t1", id)
			reason := ex.Results[0].DenialReason
			if ex.Results[0].ActionID != a.ID || ex.Results[0].ActionName != a.Name {
				t.Fatalf("lost Action provenance: %+v", ex.Results[0])
			}
			if reason != tc.want {
				t.Fatalf("denial reason = %q, want %q", reason, tc.want)
			}
			if (ex.Results[0].ErrorID != "") != tc.failure {
				t.Fatalf("error conflated with denial: %+v", ex.Results[0])
			}
		})
	}
}

// A cached VM may print a credential after its request context has gone away.
func TestActionConsoleCachedCredential(t *testing.T) {
	for _, secret := range []string{"prior-request-secret", "line\nbreak\"secret", "prefix-middle-suffix"} {
		t.Run(secret, func(t *testing.T) {
			h := newHarness(t)
			a := h.action("t1", trigLogin, "cached", `let prior;exports.onExecutePostLogin=(e)=>{if(!prior){prior=e.user.email;return;} console.log(prior); console.log(JSON.stringify(prior));console.log('x'.repeat(2040)+prior);};`, nil, false)
			h.bind("t1", trigLogin, a)
			in := h.loginInput("t1")
			in.User.Email = secret
			if _, err := h.eng.PostLogin(logscrub.WithCredentials(context.Background(), secret), in); err != nil {
				t.Fatal(err)
			}
			out, err := h.eng.PostLogin(context.Background(), h.loginInput("t1"))
			if err != nil {
				t.Fatal(err)
			}
			lines := h.execution("t1", out.ExecutionID).Results[0].Logs
			if len(lines) != 3 {
				t.Fatalf("logs=%q", lines)
			}
			for _, line := range lines {
				if strings.Contains(line, secret) || strings.Contains(line, "prior-request") || strings.Contains(line, "break") || strings.Contains(line, "prefix-") {
					t.Fatalf("cached credential leaked: %q", line)
				}
			}
		})
	}
}
func TestActionConsolePermanentMuteCapture(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			a := h.action("t1", trigLogin, "mute", `exports.onExecutePostLogin=()=>console.log('business proceeds');`, nil, false)
			h.bind("t1", trigLogin, a)
			values := []string{strings.Repeat("s", 64*1024+1)}
			if kind == "count" {
				values = nil
				for i := 0; i < 257; i++ {
					values = append(values, fmt.Sprintf("secret-%d", i))
				}
			}
			for _, ctx := range []context.Context{logscrub.WithCredentials(context.Background(), values...), context.Background()} {
				out, err := h.eng.PostLogin(ctx, h.loginInput("t1"))
				if err != nil {
					t.Fatal(err)
				}
				if lines := h.execution("t1", out.ExecutionID).Results[0].Logs; len(lines) != 0 {
					t.Fatalf("muted capture=%q", lines)
				}
			}
		})
	}
}
