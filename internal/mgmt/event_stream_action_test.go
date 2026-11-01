package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Enabling the inventory must make the real Management Action -> stream path usable.
func TestEventStreamTriggerSupported(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	w, out := e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/api/v2/actions/actions", map[string]any{"name": "Stream action", "supported_triggers": []any{map[string]any{"id": "event-stream", "version": "v1"}}, "code": `exports.onExecuteEventStream=(e,a)=>{if(e.message.id!=='evt_management')throw Error('message');a.cache.set('management','ok');console.log('management execution')}`}, e.h.CreateAction)
	if w.Code != 201 {
		t.Fatalf("create action %d %s", w.Code, w.Body)
	}
	a := out.(map[string]any)
	trigger := a["supported_triggers"].([]any)[0].(map[string]any)
	if trigger["version"] != "v1" {
		t.Fatal(trigger)
	}
	var stream any
	body := eventStreamBody("Action stream", "action")
	body["destination"].(map[string]any)["configuration"].(map[string]any)["action_id"] = a["id"]
	w, stream = eventStreamCall(t, e, "POST", "", body)
	if w.Code != 201 {
		t.Fatalf("create stream %d %s", w.Code, w.Body)
	}

	// Build and deploy through the same real Management handlers, then deliver
	// via the queue and inspect the execution through the public read endpoint.
	id := a["id"].(string)
	for {
		stored, err := e.st.Actions().GetAction(t.Context(), e.tn.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		build, err := e.st.Actions().GetBuild(t.Context(), e.tn.ID, stored.DraftBuildID)
		if err != nil {
			t.Fatal(err)
		}
		if build.Status == store.BuildBuilt {
			break
		}
		if build.Status == store.BuildFailed {
			t.Fatal("Action build failed")
		}
		select {
		case <-t.Context().Done():
			t.Fatal("build deadline")
		case <-time.After(10 * time.Millisecond):
		}
	}
	w, _ = e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/api/v2/actions/actions/"+id+"/deploy", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, id) })
	if w.Code != 202 {
		t.Fatalf("deploy %d %s", w.Code, w.Body)
	}
	storedStream, err := e.st.Events().GetEventStream(t.Context(), e.tn.ID, stream.(map[string]any)["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&actions.Worker{Engine: ae.Engine, Store: e.st, Poll: time.Millisecond}).Run(ctx)
	}()
	defer func() { cancel(); <-done }()
	worker := eventstream.NewWorker(e.st, e.w, events.DefaultConfig(), nil, eventstream.NewActionRunner(ae.Engine), nil)
	result := worker.Deliver(t.Context(), storedStream, []byte(`{"id":"evt_management"}`))
	if len(result) != 1 || result[0].Status != "success" {
		t.Fatal(result)
	}
	executions, err := e.st.Actions().ListExecutions(t.Context(), e.tn.ID, store.ExecutionFilter{Trigger: "event-stream"})
	if err != nil || len(executions) != 1 {
		t.Fatalf("executions %+v %v", executions, err)
	}
	executionID := executions[0].ID
	w, _ = e.call(t, e.tn, m2mCaller("read:actions"), "GET", "/api/v2/actions/executions/"+executionID, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionExecution(w, r, executionID) })
	if w.Code != 200 || !strings.Contains(w.Body.String(), "event-stream") {
		t.Fatalf("execution read %d %s", w.Code, w.Body)
	}
}
