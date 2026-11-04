package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Removing durable dispatch, exact handler selection, event cloning or cache support breaks delivery.
func actionEnv(t *testing.T, code string) (*Worker, *actionstest.Env, *store.EventStream) {
	t.Helper()
	w, st, _ := testWorker(t, 204)
	env := actionstest.NewOffline(t, st, w.keys)
	a := env.Deploy(t, "t", "event-stream", "events", code)
	s := &store.EventStream{TenantID: "t", ID: "est_action", DestType: "action", Config: map[string]any{"action_id": a.ID}}
	w.runner = NewActionRunner(env.Engine)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&actions.Worker{Engine: env.Engine, Store: st, Poll: time.Millisecond}).Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return w, env, s
}

func TestActionDestinationSuccess(t *testing.T) {
	w, _, s := actionEnv(t, `exports.onExecutePostLogin=()=>{throw Error('wrong handler')}; exports.onExecuteEventStream=(e,a)=>{if(Object.keys(e).sort().join(',')!=='message,secrets'||e.message.id!=='evt_original'||e.message.data.password!=='customer-value')throw Error('event changed');if(Object.keys(a).join(',')!=='cache')throw Error('capabilities');a.cache.set('seen','yes');if(a.cache.get('seen').value!=='yes')throw Error('cache');e.message.id='changed';}`)
	body := []byte(`{"id":"evt_original","data":{"password":"customer-value"},"a0stream":"est_action"}`)
	attempts := w.Deliver(t.Context(), s, body)
	if len(attempts) != 1 || attempts[0].Status != "success" {
		t.Fatalf("delivery: %+v", attempts)
	}
	if !strings.Contains(string(body), "evt_original") {
		t.Fatal("input mutated")
	}
}

func TestActionDestinationThrowRetries(t *testing.T) {
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=(e,a)=>{if(e.message.id!=='evt_original')throw Error('mutated payload');e.message.id='changed';throw Error('receiver failed');}`)
	attempts := w.Deliver(t.Context(), s, []byte(`{"id":"evt_original"}`))
	if len(attempts) != 4 {
		t.Fatalf("attempts %+v", attempts)
	}
	for _, a := range attempts {
		if a.Status != "failed" || !strings.HasPrefix(a.ErrorMessage, "action_error:") || !strings.Contains(a.ErrorMessage, "receiver failed") {
			t.Fatal(a)
		}
	}
	executions, err := env.Store.Actions().ListExecutions(t.Context(), "t", store.ExecutionFilter{Trigger: "event-stream", Take: 100})
	if err != nil || len(executions) != 4 {
		t.Fatalf("executions %+v %v", executions, err)
	}
	jobs := map[string]bool{}
	for _, ex := range executions {
		if len(ex.Results) != 1 || ex.Results[0].JobID == "" {
			t.Fatal(ex)
		}
		jobs[ex.Results[0].JobID] = true
	}
	if len(jobs) != 4 {
		t.Fatal("retry reused a durable job")
	}
}

func TestActionSecretsMasked(t *testing.T) {
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=(e)=>{console.log(e.secrets.KEY,JSON.stringify(e.secrets));throw Error(e.secrets.KEY);}`)
	a, err := env.Store.Actions().GetAction(t.Context(), "t", "act_events")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.SealActionSecret(w.keys, "t", a.ID, "KEY", "EVENT_ACTION_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	a.Secrets = []store.ActionSecret{{Name: "KEY", Sealed: sealed}}
	if err = env.Store.Actions().UpdateAction(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if _, err = env.Store.Actions().Deploy(t.Context(), "t", a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.Events().DeleteEventStream(t.Context(), "t", "s"); err != nil {
		t.Fatal(err)
	}
	s.Name = "Secrets"
	s.Status = "enabled"
	s.Subscriptions = []string{"user.created"}
	if err := env.Store.Events().CreateEventStream(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	appendEvent(t, env.Store, "evt_secret", "user.created")
	if !w.runOne(t.Context()) {
		t.Fatal("worker did not handle secret Action")
	}
	delivery, err := env.Store.Events().GetDelivery(t.Context(), "t", s.ID, "evt_secret")
	if err != nil || delivery.Status != "failed" {
		t.Fatalf("failure record %+v %v", delivery, err)
	}
	attempts := delivery.Attempts
	ex, err := env.Store.Actions().ListExecutions(t.Context(), "t", store.ExecutionFilter{Trigger: "event-stream", Take: 100})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{delivery, ex, env.Logs.String()})
	if len(attempts) != 4 || len(ex) != 4 || strings.Contains(string(raw), "EVENT_ACTION_SECRET") {
		t.Fatalf("secret leaked or runs missing: %s", raw)
	}
}

func TestActionExecutionLogged(t *testing.T) {
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=(e)=>{console.log('processed',e.message.id)}`)
	if got := w.Deliver(t.Context(), s, []byte(`{"id":"evt_logged"}`)); len(got) != 1 || got[0].Status != "success" {
		t.Fatal(got)
	}
	ex, err := env.Store.Actions().ListExecutions(t.Context(), "t", store.ExecutionFilter{Trigger: "event-stream", Action: "act_events"})
	if err != nil || len(ex) != 1 || len(ex[0].Results) != 1 || !strings.Contains(strings.Join(ex[0].Results[0].Logs, " "), "evt_logged") {
		t.Fatalf("execution %+v %v", ex, err)
	}
	if _, err = env.Store.Actions().GetExecution(t.Context(), "other", ex[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross tenant execution", err)
	}
}

// A queue with no active workers must fail by the delivery deadline, cancel
// its pending job, and leave no job that can execute after a later restart.
func TestActionDestinationTimeoutCancelsQueuedJob(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	env := actionstest.NewOffline(t, st, w.keys)
	a := env.Deploy(t, "t", "event-stream", "pending", `exports.onExecuteEventStream=()=>{throw Error('late execution')}`)
	observed := make(chan string, 1)
	env.Engine.Store = observeJobStore{Store: st, ids: observed}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := NewActionRunner(env.Engine).RunEventStream(ctx, "t", a.ID, []byte(`{"id":"evt_timeout"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	var id string
	select {
	case id = <-observed:
	default:
		t.Fatal("no durable job enqueued")
	}
	j, err := st.Actions().GetJob(t.Context(), "t", id)
	if err != nil || j.Status != "failed" {
		t.Fatalf("queued cancellation %+v %v", j, err)
	}
	jobs, err := st.Actions().ClaimJobs(t.Context(), time.Now().Add(time.Hour), time.Minute, 100)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("late claim %+v %v", jobs, err)
	}
}

type observeJobStore struct {
	store.Store
	ids chan string
}

func (s observeJobStore) Actions() store.Actions {
	return observeJobs{Actions: s.Store.Actions(), ids: s.ids}
}
func (s observeJobStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(observeJobStore{Store: tx, ids: s.ids}) })
}

type observeJobs struct {
	store.Actions
	ids chan string
}

func (a observeJobs) EnqueueJob(ctx context.Context, j *store.ActionJob) error {
	err := a.Actions.EnqueueJob(ctx, j)
	if err == nil {
		a.ids <- j.ID
	}
	return err
}

// Undocumented APIs remain unavailable; a different trigger cannot be used as
// an event destination even when its code exports the event-stream handler.
func TestActionDestinationExactTriggerAndUnsupportedAPI(t *testing.T) {
	for _, code := range []string{`exports.onExecutePostLogin=()=>{}`, `exports.onExecuteEventStream=(e,a)=>a.message.fail('bad')`, `exports.onExecuteEventStream=(e,a)=>a.user.setAppMetadata('x',true)`} {
		t.Run(code, func(t *testing.T) {
			w, _, s := actionEnv(t, code)
			attempts := w.Deliver(t.Context(), s, []byte(`{"id":"evt_test"}`))
			if len(attempts) != 4 || attempts[0].Status != "failed" {
				t.Fatal(attempts)
			}
		})
	}
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=()=>{}`)
	a := env.Deploy(t, "t", "post-login", "login", `exports.onExecuteEventStream=()=>{}`)
	s.Config["action_id"] = a.ID
	if got := w.Deliver(t.Context(), s, []byte(`{"id":"evt_test"}`)); len(got) != 4 || got[0].Status != "failed" {
		t.Fatal(got)
	}
	ex, err := env.Store.Actions().ListExecutions(t.Context(), "t", store.ExecutionFilter{})
	if err != nil || len(ex) != 0 {
		t.Fatalf("wrong trigger executed %+v %v", ex, err)
	}
}

func TestActionDestinationFailedDeliveryRecorded(t *testing.T) {
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=(e)=>{throw Error('record receiver failure')}`)
	if err := env.Store.Events().DeleteEventStream(t.Context(), "t", "s"); err != nil {
		t.Fatal(err)
	}
	s.Name = "Action"
	s.Status = "enabled"
	s.Subscriptions = []string{"user.created"}
	if err := env.Store.Events().CreateEventStream(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	appendEvent(t, env.Store, "evt_failed", "user.created")
	if !w.runOne(t.Context()) {
		t.Fatal("worker did not handle event")
	}
	d, err := env.Store.Events().GetDelivery(t.Context(), "t", s.ID, "evt_failed")
	if err != nil || len(d.Attempts) != 4 || d.Status != "failed" {
		t.Fatalf("failed record %+v %v", d, err)
	}
	for _, a := range d.Attempts {
		if !strings.Contains(a.ErrorMessage, "action_error:") || !strings.Contains(a.ErrorMessage, "record receiver failure") {
			t.Fatal(a)
		}
	}
}

// A slow cancellation repository must not extend the ten-second delivery
// deadline; cancellation I/O shares the attempt's budget.
func TestActionDestinationCancellationFitsDeadline(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	env := actionstest.NewOffline(t, st, w.keys)
	a := env.Deploy(t, "t", "event-stream", "bounded", `exports.onExecuteEventStream=()=>{}`)
	env.Engine.Store = slowCancelStore{Store: st}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := NewActionRunner(env.Engine).RunEventStream(ctx, "t", a.ID, []byte(`{"id":"evt_bounded"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	// A cancellation that ignored the deadline would block until the test
	// context ends; 1s leaves room for -race on busy CI hosts.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation exceeded delivery deadline: %v", elapsed)
	}
}

type slowCancelStore struct{ store.Store }

func (s slowCancelStore) Actions() store.Actions { return slowCancelActions{s.Store.Actions()} }
func (s slowCancelStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(slowCancelStore{tx}) })
}

type slowCancelActions struct{ store.Actions }

func (a slowCancelActions) CancelJob(ctx context.Context, tid, id string) error {
	if strings.HasPrefix(id, "ajob_") {
		<-ctx.Done()
		return ctx.Err()
	}
	return a.Actions.CancelJob(ctx, tid, id)
}

func TestActionDestinationTimeoutClassification(t *testing.T) {
	w, _, s := testWorker(t, 204)
	s.DestType = "action"
	s.Config = map[string]any{"action_id": "act_timeout"}
	s.SealedSecret = nil
	w.runner = runnerFunc(func(context.Context, string, string, []byte) error { return context.DeadlineExceeded })
	attempts := w.Deliver(t.Context(), s, []byte(`{"id":"evt_timeout"}`))
	if len(attempts) != 4 || attempts[0].ErrorMessage != "timeout" {
		t.Fatal(attempts)
	}
}

func TestActionDestinationRuntimeTimeoutClassification(t *testing.T) {
	w, env, s := actionEnv(t, `exports.onExecuteEventStream=async()=>{await new Promise(()=>{})}`)
	env.Engine.FlowBudget = 100 * time.Millisecond
	attempts := w.Deliver(t.Context(), s, []byte(`{"id":"evt_timeout"}`))
	if len(attempts) != 4 || attempts[0].ErrorMessage != "timeout" {
		t.Fatal(attempts)
	}
}
