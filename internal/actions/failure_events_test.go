package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSynchronousActionFailureEvents(t *testing.T) {
	for _, tc := range []struct {
		name, body            string
		pre, timeout, failure bool
		failUpdate, failExec  bool
	}{
		{name: "post login throw", body: `throw Error('private '+e.secrets.KEY)`, failure: true},
		{name: "post login timeout", body: `await new Promise(r=>setTimeout(r,1000))`, timeout: true, failure: true},
		{name: "pre registration throw", body: `throw Error('private')`, pre: true, failure: true},
		{name: "explicit deny", body: `a.access.deny('refused')`},
		{name: "validation error", body: `a.validation.error('invalid_signup','refused')`, pre: true},
		{name: "success", body: ``},
		{name: "metadata commit failure", body: `a.user.setAppMetadata('key','value')`, failUpdate: true, failure: true},
		{name: "execution record failure", body: ``, failExec: true, failure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tr, handler := trigLogin, "onExecutePostLogin"
			if tc.pre {
				tr, handler = actions.TriggerPreUserRegistration, "onExecutePreUserRegistration"
			}
			action := h.action("t1", tr, "name-q", `exports.`+handler+`=async(e,a)=>{`+tc.body+`};`, map[string]string{"KEY": "z"}, false)
			h.bind("t1", tr, action)
			if tc.timeout {
				h.eng.FlowBudget = 100 * time.Millisecond
			}
			recorder := logs.NewRecorder(h.st, logs.Config{}, slog.New(slog.DiscardHandler))
			h.eng.Recorder = recorder
			ctx := logs.WithRecorder(logscrub.WithCredentials(context.Background(), "q", "e"), recorder)
			in := h.loginInput("t1")
			in.Client.Name = "z"
			if tc.failUpdate || tc.failExec {
				h.eng.Store = failingStore{Store: h.st, failUpdate: tc.failUpdate, failExec: tc.failExec}
			}
			var err error
			if tc.pre {
				_, err = h.eng.PreUserRegistration(ctx, actions.RegistrationInput{Tenant: in.Tenant, Client: in.Client, Connection: in.Connection, User: in.User})
			} else {
				_, err = h.eng.PostLogin(ctx, in)
			}
			if (err != nil) != tc.failure {
				t.Fatalf("err=%v", err)
			}
			if e := recorder.Flush(context.Background()); e != nil {
				t.Fatal(e)
			}
			events, _, err2 := h.st.Logs().SearchLogs(context.Background(), "t1", nil, store.LogPage{PerPage: 20})
			if err2 != nil {
				t.Fatal(err2)
			}
			if !tc.failure {
				if len(events) != 0 {
					t.Fatalf("nonfailure=%+v", events)
				}
				return
			}
			var fe *actions.ErrFlow
			if !errors.As(err, &fe) || fe.ExecutionID == "" {
				t.Fatalf("missing execution: %v", err)
			}
			if len(events) != 1 || events[0].Type != "actions_execution_failed" || events[0].ClientID != logscrub.MaskText(ctx, in.Client.ClientID) {
				t.Fatalf("events=%+v", events)
			}
			var doc map[string]any
			_ = json.Unmarshal(events[0].Body, &doc)
			date, ok := doc["date"].(string)
			if _, parseErr := time.Parse(time.RFC3339Nano, date); !ok || parseErr != nil {
				t.Fatalf("canonical date=%s", events[0].Body)
			}
			details, _ := doc["details"].(map[string]any)
			links, _ := details["actions"].(map[string]any)
			ids, _ := links["executions"].([]any)
			if len(ids) != 1 || ids[0] != fe.ExecutionID || doc["date"] == "" || doc["type"] != "actions_execution_failed" {
				t.Fatalf("schema=%s", events[0].Body)
			}
			if doc["client_name"] != logscrub.Marker {
				t.Fatalf("opened short Action secret not masked: %s", events[0].Body)
			}
			if strings.Contains(string(events[0].Body), "private") || strings.Contains(string(events[0].Body), "name-q") {
				t.Fatalf("unsafe event=%s", events[0].Body)
			}
			if !tc.pre && events[0].UserID != in.User.UserID {
				t.Fatalf("user=%s", events[0].Body)
			}
		})
	}
}

func TestSynchronousActionPrestartHasNoExecutionEvent(t *testing.T) {
	h := newHarness(t)
	capture := &actionOutcomeRecorder{events: make(chan logs.Event, 2)}
	h.eng.Recorder = capture
	h.eng.Store = prestartFailureStore{h.st}
	_, err := h.eng.PostLogin(context.Background(), h.loginInput("t1"))
	var failure *actions.ErrFlow
	if !errors.As(err, &failure) || failure.ExecutionID != "" {
		t.Fatalf("prestart=%v", err)
	}
	select {
	case event := <-capture.events:
		t.Fatalf("invented execution event=%+v", event)
	default:
	}
}

type prestartFailureStore struct{ store.Store }

func (s prestartFailureStore) Actions() store.Actions {
	return prestartFailureActions{s.Store.Actions()}
}

type prestartFailureActions struct{ store.Actions }

func (s prestartFailureActions) Bindings(context.Context, string, string) ([]store.BoundVersion, error) {
	return nil, errors.New("private lookup failure")
}
