package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestFlowCredentialSnapshotsAndIsolation(t *testing.T) {
	st := tenantStore(t)
	recorder := NewRecorder(st, Config{}, quiet())
	outer := WithRecorder(context.Background(), recorder)
	child := logscrub.WithValues(outer, "child-only-mask")
	AddCredentials(child, "first")
	RecordEvent(outer, recorder, Event{TenantID: "t", Type: "f", ClientName: "first second"})
	AddCredentials(child, "second")
	RecordEvent(outer, recorder, Event{TenantID: "t", Type: "f", ClientName: "first second"})
	independent := WithRecorder(context.Background(), recorder)
	RecordEvent(independent, recorder, Event{TenantID: "t", Type: "f", ClientName: "first second"})
	if got := logscrub.MaskText(outer, "first second child-only-mask"); got != "first second child-only-mask" {
		t.Fatalf("generic immutable masks changed: %q", got)
	}
	if err := recorder.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(context.Background(), "t", nil, store.LogPage{PerPage: 20, Ascending: true})
	if err != nil || len(rows) != 3 {
		t.Fatal(rows, err)
	}
	want := []string{logscrub.Marker + " second", logscrub.Marker + " " + logscrub.Marker, "first second"}
	for i, row := range rows {
		var doc map[string]any
		if err := json.Unmarshal(row.Body, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["client_name"] != want[i] {
			t.Fatalf("snapshot %d=%s want=%q", i, row.Body, want[i])
		}
	}
}

func TestFlowCredentialLimitsDropUnsafeEvents(t *testing.T) {
	for _, limit := range []string{"count", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			st := tenantStore(t)
			recorder := NewRecorder(st, Config{}, quiet())
			ctx := WithRecorder(context.Background(), recorder)
			if limit == "count" {
				for i := 0; i < 256; i++ {
					AddCredentials(ctx, fmt.Sprintf("credential-%d", i))
				}
			} else {
				AddCredentials(ctx, strings.Repeat("x", 64<<10))
			}
			// Duplicate/empty values cannot exhaust an otherwise safe request trace.
			AddCredentials(ctx, "")
			if limit == "count" {
				AddCredentials(ctx, "credential-0")
			}
			RecordEvent(ctx, recorder, Event{TenantID: "t", Type: "f", ClientName: "safe-before-overflow"})
			AddCredentials(ctx, "overflow")
			RecordEvent(ctx, recorder, Event{TenantID: "t", Type: "f", ClientName: "overflow"})
			// Recorder/context wrapping cannot reset the unsafe state within a request.
			RecordEvent(WithRecorder(ctx, recorder), recorder, Event{TenantID: "t", Type: "f", ClientName: "overflow"})
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			rows, _, err := st.Logs().SearchLogs(context.Background(), "t", nil, store.LogPage{PerPage: 20})
			if err != nil || len(rows) != 1 {
				t.Fatalf("unsafe events=%+v err=%v", rows, err)
			}
		})
	}
}

func TestFlowCredentialsConcurrentSnapshots(t *testing.T) {
	st := tenantStore(t)
	recorder := NewRecorder(st, Config{}, quiet())
	ctx := WithRecorder(context.Background(), recorder)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			credential := fmt.Sprintf("credential-%03d", i)
			AddCredentials(ctx, credential)
			RecordEvent(ctx, recorder, Event{TenantID: "t", Type: "f", ClientName: credential})
		}(i)
	}
	wg.Wait()
	if err := recorder.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(context.Background(), "t", nil, store.LogPage{PerPage: 100})
	if err != nil || len(rows) != 64 {
		t.Fatal(len(rows), err)
	}
	for _, row := range rows {
		var doc map[string]any
		_ = json.Unmarshal(row.Body, &doc)
		if doc["client_name"] != logscrub.Marker {
			t.Fatalf("concurrent leak=%s", row.Body)
		}
	}
}
