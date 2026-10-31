package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMountedSilentActionCredentialMasks(t *testing.T) {
	for _, secret := range []string{"q", "mounted-action-credential"} {
		for _, outcome := range []string{"throw", "deny"} {
			t.Run(outcome+"/"+secret, func(t *testing.T) {
				var recorder *logs.AsyncRecorder
				var ae *actionstest.Env
				e := newFlowEnvSeed(t, flowSeed, func(d *Deps) {
					recorder = logs.NewRecorder(d.Store, logs.Config{}, slog.New(slog.DiscardHandler))
					d.Recorder = recorder
					ae = actionstest.NewOffline(t, d.Store, d.Wrapper)
					d.Actions = ae.Engine
				})
				ctx := context.Background()
				client := e.client(t)
				e.codeFlow(t, client)
				tn, _ := e.st.Tenants().GetByName(ctx, "flow")
				code := `exports.onExecutePostLogin=(event,api)=>{throw Error(event.secrets.KEY)};`
				if outcome == "deny" {
					code = `exports.onExecutePostLogin=(event,api)=>api.access.deny(event.secrets.KEY);`
				}
				action := ae.Deploy(t, tn.ID, actions.TriggerPostLogin, "mask-outcome", code)
				action, err := e.st.Actions().GetAction(ctx, tn.ID, action.ID)
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := keys.SealActionSecret(e.w, tn.ID, action.ID, "KEY", secret)
				if err != nil {
					t.Fatal(err)
				}
				action.Secrets = []store.ActionSecret{{Name: "KEY", Sealed: sealed}}
				if err := e.st.Actions().UpdateAction(ctx, action); err != nil {
					t.Fatal(err)
				}
				if _, err := e.st.Actions().Deploy(ctx, tn.ID, action.ID, ""); err != nil {
					t.Fatal(err)
				}
				ae.Bind(t, tn.ID, actions.TriggerPostLogin, action)
				app, err := e.st.Clients().Get(ctx, tn.ID, "spa")
				if err != nil {
					t.Fatal(err)
				}
				app.Name = secret
				if err := e.st.Clients().Update(ctx, app); err != nil {
					t.Fatal(err)
				}
				response, _ := fetch(t, client, authorizeURL(e.base, "prompt", "none"))
				location, err := response.Location()
				expectedError := "server_error"
				if outcome == "deny" {
					expectedError = "access_denied"
				}
				if err != nil || location.Query().Get("error") != expectedError {
					t.Fatalf("outcome=%d %v %v", response.StatusCode, location, err)
				}
				if err := recorder.Flush(ctx); err != nil {
					t.Fatal(err)
				}
				events, _, err := e.st.Logs().SearchLogs(ctx, tn.ID, nil, store.LogPage{PerPage: 20, Ascending: true})
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"s", "seacft"}
				if outcome == "throw" {
					want = append(want, "actions_execution_failed")
				}
				want = append(want, "f", "fsa")
				codes := []string{}
				var executionID string
				for index, event := range events {
					codes = append(codes, event.Type)
					if index < 2 {
						continue
					}
					var doc map[string]any
					if err := json.Unmarshal(event.Body, &doc); err != nil {
						t.Fatal(err)
					}
					if doc["client_name"] != logscrub.Marker || event.ClientID != "spa" || event.UserID == "" {
						t.Errorf("flow credential leak=%s", event.Body)
					}
					date, ok := doc["date"].(string)
					if _, err := time.Parse(time.RFC3339Nano, date); !ok || err != nil || doc["type"] != event.Type {
						t.Fatalf("schema=%s", event.Body)
					}
					links := doc["details"].(map[string]any)["actions"].(map[string]any)["executions"].([]any)
					if len(links) != 1 {
						t.Fatalf("links=%s", event.Body)
					}
					id := links[0].(string)
					if executionID == "" {
						executionID = id
					}
					if id != executionID {
						t.Fatalf("different flow executions=%s", event.Body)
					}
					if _, err := e.st.Actions().GetExecution(ctx, tn.ID, id); err != nil {
						t.Fatal(err)
					}
					if secret != "q" && strings.Contains(string(event.Body), secret) {
						t.Fatalf("raw credential=%s", event.Body)
					}
				}
				if !slices.Equal(codes, want) {
					t.Fatalf("codes=%v want=%v", codes, want)
				}
			})
		}
	}
}
