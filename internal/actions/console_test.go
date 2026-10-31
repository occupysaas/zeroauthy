package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
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
		})
	}
}

func TestActionConsoleEscapedScalarCredential(t *testing.T) {
	for _, password := range []string{"line\nbreak\"value", `"quoted-secret"`, `{"value":"json-secret"}`} {
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
