package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestShortCredentialEventPreservesSchema(t *testing.T) {
	st := memory.New()
	if err := st.Tenants().Create(context.Background(), &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"a", "s", "1", "猫"} {
		t.Run(secret, func(t *testing.T) {
			r := NewRecorder(st, Config{}, slog.New(slog.DiscardHandler))
			ctx := logscrub.WithCredentials(context.Background(), secret)
			RecordEvent(ctx, r, Event{TenantID: "tenant", Type: "s", UserName: secret, Details: map[string]any{"nested": map[string]any{secret: secret}}, ExecutionIDs: []string{"exe_unique"}})
			if err := r.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := st.Logs().SearchLogs(context.Background(), "tenant", nil, store.LogPage{PerPage: 100, Ascending: false})
			if err != nil || len(events) == 0 {
				t.Fatal(events, err)
			}
			var body map[string]any
			if err := json.Unmarshal(events[0].Body, &body); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"date", "type", "description", "user_name", "details"} {
				if _, ok := body[key]; !ok {
					t.Fatalf("missing schema key %s: %s", key, events[0].Body)
				}
			}
			if body["type"] != "s" {
				t.Fatalf("type=%v", body["type"])
			}
			if _, err := time.Parse(time.RFC3339Nano, body["date"].(string)); err != nil {
				t.Fatal(err)
			}
			if body["user_name"] != logscrub.Marker {
				t.Fatalf("user_name=%v", body["user_name"])
			}
			details := body["details"].(map[string]any)
			actions, ok := details["actions"].(map[string]any)
			if !ok {
				t.Fatalf("missing actions: %v", details)
			}
			if _, ok := actions["executions"]; !ok {
				t.Fatalf("missing executions: %v", actions)
			}
		})
	}
}

func TestShortCredentialEventPreservesGeneratedExecutionID(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	ctx := logscrub.WithCredentials(context.Background(), "a")
	id := "exe_aaaaaaaaaaaaaaaaaaaaaaaa"
	RecordEvent(ctx, r, Event{TenantID: "t", Type: "ss", ExecutionIDs: []string{id, "a"}})
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(ctx, "t", nil, store.LogPage{PerPage: 1})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var body map[string]any
	if err = json.Unmarshal(rows[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	ids := body["details"].(map[string]any)["actions"].(map[string]any)["executions"].([]any)
	if ids[0] != id || ids[1] != logscrub.Marker {
		t.Fatal(ids)
	}
}

func TestCanonicalLookingCredentialInDynamicDetailsMasked(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	credential := "exe_aaaaaaaaaaaaaaaaaaaaaaaa"
	ctx := logscrub.WithCredentials(context.Background(), credential)
	RecordEvent(ctx, r, Event{TenantID: "t", Type: "f", Details: map[string]any{"actions": map[string]any{"executions": []string{credential}}}})
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(ctx, "t", nil, store.LogPage{PerPage: 1})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if bytes.Contains(rows[0].Body, []byte(credential)) {
		t.Fatalf("untrusted details credential preserved: %s", rows[0].Body)
	}
}

func TestEventStrategyTypes(t *testing.T) {
	for _, tc := range []struct{ strategy, want string }{{"auth0", "database"}, {"google-oauth2", "social"}, {"oauth2", "social"}, {"windowslive", "social"}, {"oidc", "enterprise"}, {"waad", "enterprise"}, {"", ""}, {"future-unknown", ""}} {
		t.Run(tc.strategy, func(t *testing.T) {
			if got := StrategyType(tc.strategy); got != tc.want {
				t.Fatalf("strategy type=%q want=%q", got, tc.want)
			}
		})
	}
}
