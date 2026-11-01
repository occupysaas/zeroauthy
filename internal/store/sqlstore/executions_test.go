package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestExecutionConsole(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.ExecutionConsole(t, mustOpen(t, mk(t))) })
	}
}
func TestExecutionUpgrade29(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			st := openAtVersion(t, mk(t), 29)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			if err := st.Tenants().Create(ctx, &store.Tenant{ID: "old", Name: "old"}); err != nil {
				t.Fatal(err)
			}
			// Version 29 records have neither console nor immutable Action IDs.
			if _, err := st.exec(ctx, `INSERT INTO action_executions (`+execCols+`) VALUES (?,?,?,?,?,?,?)`, "old", "legacy", "post-login", "final", `[{"ActionName":"old-name"}]`, micros(now), micros(now)); err != nil {
				t.Fatal(err)
			}
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			p, err := st.Actions().ListExecutions(ctx, "old", store.ExecutionFilter{})
			if err != nil || len(p) != 1 || p[0].ID != "legacy" {
				t.Fatalf("legacy=%+v %v", p, err)
			}
			p, err = st.Actions().ListExecutions(ctx, "old", store.ExecutionFilter{Action: "old-name"})
			if err != nil || len(p) != 0 {
				t.Fatalf("identity guessed=%+v %v", p, err)
			}
			ex := &store.Execution{TenantID: "old", ID: "new", Trigger: "post-login", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{ActionID: "act", Logs: []string{"safe"}}}}
			if err := st.Actions().CreateExecution(ctx, ex); err != nil {
				t.Fatal(err)
			}
			p, err = st.Actions().ListExecutions(ctx, "old", store.ExecutionFilter{Action: "act"})
			if err != nil || len(p) != 1 || p[0].Results[0].Logs[0] != "safe" {
				t.Fatalf("new=%+v %v", p, err)
			}
			if _, err := st.Actions().PurgeExecutions(ctx, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := st.queryRow(ctx, `SELECT COUNT(*) FROM action_execution_actions`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("projection purge=%d %v", n, err)
			}
		})
	}
}
