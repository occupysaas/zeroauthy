package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ExecutionConsole exercises immutable console storage and bounded keyset paging.
func ExecutionConsole(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, tid := range []string{"exec-t1", "exec-t2"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}); err != nil {
			t.Fatal(err)
		}
	}
	a := st.Actions()
	for _, id := range []string{"A", "a", "b", "c"} {
		ex := &store.Execution{TenantID: "exec-t1", ID: id, Trigger: "post-login", Status: "final", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{ActionID: "deleted-action", ActionName: "old-name", Logs: []string{"safe"}, DenialReason: "Blocked [REDACTED]"}}}
		if err := a.CreateExecution(ctx, ex); err != nil {
			t.Fatal(err)
		}
		ex.Results[0].Logs[0] = "bad"
		ex.Results[0].DenialReason = "mutated"
		got, err := a.GetExecution(ctx, "exec-t1", id)
		if err != nil || got.Results[0].Logs[0] != "safe" || got.Results[0].DenialReason != "Blocked [REDACTED]" {
			t.Fatalf("immutable input=%+v %v", got, err)
		}
		got.Results[0].Logs[0] = "bad"
		got.Results[0].DenialReason = "mutated"
		got, _ = a.GetExecution(ctx, "exec-t1", id)
		if got.Results[0].Logs[0] != "safe" || got.Results[0].DenialReason != "Blocked [REDACTED]" {
			t.Fatal("mutable read")
		}
	}
	page, err := a.ListExecutions(ctx, "exec-t1", store.ExecutionFilter{Take: 2, Action: "deleted-action", Trigger: "post-login"})
	if err != nil || len(page) != 2 || page[0].ID != "c" || page[1].ID != "b" {
		t.Fatalf("page=%+v %v", page, err)
	}
	page, err = a.ListExecutions(ctx, "exec-t1", store.ExecutionFilter{After: "a", Take: 2})
	if err != nil || len(page) != 2 || page[0].ID != "b" || page[1].ID != "c" {
		t.Fatalf("after=%+v %v", page, err)
	}
	page, err = a.ListExecutions(ctx, "exec-t1", store.ExecutionFilter{After: "A", Take: 2})
	if err != nil || len(page) != 2 || page[0].ID != "a" || page[1].ID != "b" {
		t.Fatalf("byte-order cursor=%+v %v", page, err)
	}
	for _, f := range []store.ExecutionFilter{{Action: "missing"}, {Trigger: "missing"}} {
		p, err := a.ListExecutions(ctx, "exec-t1", f)
		if err != nil || len(p) != 0 {
			t.Fatalf("filter=%+v %v", p, err)
		}
	}
	p, err := a.ListExecutions(ctx, "exec-t2", store.ExecutionFilter{})
	if err != nil || len(p) != 0 {
		t.Fatalf("tenant=%+v %v", p, err)
	}
	if _, err := a.ListExecutions(ctx, "exec-t2", store.ExecutionFilter{After: "a"}); err != store.ErrNotFound {
		t.Fatalf("cursor tenant=%v", err)
	}
}
