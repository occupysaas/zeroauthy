package seed

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

func TestSeedEventContext(t *testing.T) {
	st := events.Wrap(memory.New(), events.Config{})
	f, err := Parse([]byte(`tenants:
 - name: context
   domains: [context.example.test]
   connections: [{name: Database}]
   users: [{connection: Database, email: context@example.test, password: "long enough pw"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := events.WithContext(context.Background(), events.Context{ClientID: "caller", ConnectionID: "connection", Method: "POST", Hostname: "request"})
	if err := Apply(ctx, st, f, time.Now, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "context")
	if err != nil {
		t.Fatal(err)
	}
	c := capturedContext(t, st, tn.ID, "user.created")
	if len(c) != 1 || c["tenant"].(map[string]any)["id"] != tn.ID {
		t.Fatal(c)
	}
}
