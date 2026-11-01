package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func capturedContext(t *testing.T, st store.Store, tid, typ string) map[string]any {
	t.Helper()
	rows, err := st.Events().EventsAfter(context.Background(), tid, 0, []string{typ}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("events %s: count=%d err=%v", typ, len(rows), err)
	}
	var body map[string]any
	if err := json.Unmarshal(rows[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	return body["data"].(map[string]any)["context"].(map[string]any)
}

func TestImportEventContext(t *testing.T) {
	e := newImpEnv(t, memory.New())
	tn, err := e.st.Tenants().Get(context.Background(), impTenant)
	if err != nil {
		t.Fatal(err)
	}
	tn.CanonicalHost = "acme.example.test"
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	st := events.Wrap(e.st, events.Config{})
	e.newJob(fileOf(t, []any{map[string]any{"email": "import@example.test"}}), nil)
	j, lease := e.claim("owner")
	ctx := events.WithContext(context.Background(), events.Context{ClientID: "leaked-client", ConnectionID: "leaked-connection", Method: "POST", Hostname: "leaked-host"})
	status, _, err := e.importer().Run(ctx, st, j, lease)
	if err != nil || status != store.JobCompleted {
		t.Fatalf("run=%s %v", status, err)
	}
	c := capturedContext(t, st, impTenant, "user.created")
	if len(c) != 1 || c["tenant"].(map[string]any)["id"] != impTenant {
		t.Fatal(c)
	}
}
