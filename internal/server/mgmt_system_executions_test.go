package server

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSystemExecutionsTargetGrant(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	acme, _ := st.Tenants().GetByName(ctx, "acme")
	now := time.Now().UTC()
	if err := st.Actions().CreateExecution(ctx, &store.Execution{TenantID: acme.ID, ID: "console", Trigger: "post-login", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{Logs: []string{"safe console"}}}}); err != nil {
		t.Fatal(err)
	}
	_, uid := tenantOperatorToken(t, st, "execution-target@example.test", []string{"*"})
	sys := mustSystemID(t, st)
	setGrants := func(names ...string) {
		t.Helper()
		if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sys, UserID: uid, Tenants: names}); err != nil {
			t.Fatal(err)
		}
	}
	setGrants("acme")
	limited := mintTargetOperator(t, st, uid, []string{"acme"})
	base := "https://" + mgmtSystemHost + "/api/system/tenants/acme/actions/executions"
	for _, path := range []string{base, base + "/console"} {
		if rec, _ := sendRaw(h, "GET", path, limited, nil); rec.Code != 200 {
			t.Fatalf("target-only grant %s=%d %s", path, rec.Code, rec.Body)
		}
	}
	systemOnly := mintTargetOperator(t, st, uid, []string{"system"})
	for _, path := range []string{base, base + "/console"} {
		if rec, _ := sendRaw(h, "GET", path, systemOnly, nil); rec.Code != 403 {
			t.Fatalf("signed target grant %s=%d", path, rec.Code)
		}
	}
	setGrants("system")
	for _, path := range []string{base, base + "/console"} {
		if rec, _ := sendRaw(h, "GET", path, limited, nil); rec.Code != 403 {
			t.Fatalf("live target grant %s=%d", path, rec.Code)
		}
	}
	setGrants("acme")
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/system/tenants/acme/actions/executions", limited, nil); rec.Code != 404 {
		t.Fatalf("tenant host=%d", rec.Code)
	}
	if rec, _ := sendRaw(h, "GET", base, "", nil); rec.Code != 401 {
		t.Fatalf("unauthenticated=%d", rec.Code)
	}
}
