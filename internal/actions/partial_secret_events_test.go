package actions_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The first credential opens, while a later envelope in the same Action or
// Module is corrupt. The actual failed execution still emits safe metadata.
func TestPartialSecretOpenFailureEventMasked(t *testing.T) {
	for _, kind := range []string{"action", "module"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			const opened = "partially-opened-credential"
			var values map[string]string
			if kind == "action" {
				values = map[string]string{"FIRST": opened}
			}
			action := h.action("t1", trigLogin, "partial", `exports.onExecutePostLogin=()=>{};`, values, false)
			if kind == "module" {
				m, v := moduleFixture(t, h, "t1", "partial", "exports.ok=true;", map[string]string{"FIRST": opened})
				pinModule(t, h, action, m, v)
			}
			h.bind("t1", trigLogin, action)
			h.eng.Store = partialSecretStore{Store: h.st, kind: kind}
			recorder := logs.NewRecorder(h.st, logs.Config{}, slog.New(slog.DiscardHandler))
			h.eng.Recorder = recorder
			ctx := logs.WithRecorder(context.Background(), recorder)
			in := h.loginInput("t1")
			in.Client.Name = opened
			if _, err := h.eng.PostLogin(ctx, in); err == nil {
				t.Fatal("corrupt second credential unexpectedly opened")
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := h.st.Logs().SearchLogs(context.Background(), "t1", nil, store.LogPage{PerPage: 20})
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Type != "actions_execution_failed" {
				t.Fatalf("events=%+v", events)
			}
			var doc map[string]any
			if err := json.Unmarshal(events[0].Body, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["client_name"] != logscrub.Marker {
				t.Fatalf("previously opened credential leaked: %s", events[0].Body)
			}
		})
	}
}

type partialSecretStore struct {
	store.Store
	kind string
}

func (s partialSecretStore) Actions() store.Actions {
	return partialSecretActions{Actions: s.Store.Actions(), kind: s.kind}
}

type partialSecretActions struct {
	store.Actions
	kind string
}

func (s partialSecretActions) Bindings(ctx context.Context, tid, trigger string) ([]store.BoundVersion, error) {
	bound, err := s.Actions.Bindings(ctx, tid, trigger)
	if err == nil && s.kind == "action" {
		bound[0].Version.Secrets = append(bound[0].Version.Secrets, store.ActionSecret{Name: "BROKEN", Sealed: []byte("corrupt second envelope")})
	}
	return bound, err
}
func (s partialSecretActions) GetModuleVersion(ctx context.Context, tid, moduleID, versionID string) (*store.ActionModuleVersion, error) {
	version, err := s.Actions.GetModuleVersion(ctx, tid, moduleID, versionID)
	if err == nil && s.kind == "module" {
		version.Secrets = append(version.Secrets, store.ActionSecret{Name: "BROKEN", Sealed: []byte("corrupt second envelope")})
	}
	return version, err
}
