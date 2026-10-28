package server

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestSystemActionExecutionAttempt(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	op, _ := operatorToken(t, st, "attempt-op@example.test")
	acme, _ := st.Tenants().GetByName(ctx, "acme")
	now := time.Now().UTC()
	for _, ex := range []*store.Execution{
		{TenantID: acme.ID, ID: "async", Trigger: "custom-email-provider", Status: "final", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{JobID: "ajob_123", JobAttempt: 3}}},
		{TenantID: acme.ID, ID: "sync", Trigger: "post-login", Status: "final", CreatedAt: now, UpdatedAt: now},
	} {
		if err := st.Actions().CreateExecution(ctx, ex); err != nil {
			t.Fatal(err)
		}
	}
	base := "https://" + mgmtSystemHost + "/api/system/tenants/acme/actions/executions/"
	rec, body := sendRaw(h, "GET", base+"async/attempt", op, nil)
	m, _ := body.(map[string]any)
	if rec.Code != 200 || m["job_id"] != "ajob_123" || m["attempt"] != float64(3) {
		t.Fatalf("attempt %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "GET", base+"sync/attempt", op, nil); rec.Code != 204 {
		t.Fatalf("sync %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "GET", base+"missing/attempt", op, nil); rec.Code != 404 {
		t.Fatalf("missing %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "GET", base+"async/attempt", "", nil); rec.Code != 401 {
		t.Fatalf("anonymous %d", rec.Code)
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	if rec, _ := sendRaw(h, "GET", base+"async/attempt", admin, nil); rec.Code != 401 {
		t.Fatalf("m2m %d", rec.Code)
	}
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/system/tenants/acme/actions/executions/async/attempt", op, nil); rec.Code != 404 {
		t.Fatalf("tenant host %d", rec.Code)
	}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "other-attempt", Name: "other-attempt", Domains: []string{"other-attempt.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if rec, _ := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/other-attempt/actions/executions/async/attempt", op, nil); rec.Code != 404 {
		t.Fatalf("foreign execution %d", rec.Code)
	}
	_, uid := tenantOperatorToken(t, st, "attempt-limited@example.test", []string{"*"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: uid, Tenants: []string{"other-attempt"}}); err != nil {
		t.Fatal(err)
	}
	limited := mintTargetOperator(t, st, uid, []string{"acme"})
	if rec, _ := sendRaw(h, "GET", base+"async/attempt", limited, nil); rec.Code != 403 {
		t.Fatalf("persisted target grant %d", rec.Code)
	}
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: uid, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	limited = mintTargetOperator(t, st, uid, []string{"other-attempt"})
	if rec, _ := sendRaw(h, "GET", base+"async/attempt", limited, nil); rec.Code != 403 {
		t.Fatalf("signed target grant %d", rec.Code)
	}
}
