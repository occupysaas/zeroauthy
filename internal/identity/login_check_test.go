package identity

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestLoginWithCheckCustomImportOnce(t *testing.T) {
	db, conn, _ := importConn(t, memory.New(), scripts{store.ScriptLogin: func([]any) (any, error) { return map[string]any{"user_id": 42, "email": "alice@legacy.test"}, nil }})
	calls := 0
	u, err := db.LoginWithCheck(context.Background(), conn, "alice@legacy.test", "valid password", func(context.Context) error { calls++; return nil })
	if err != nil || u == nil || calls != 1 {
		t.Fatal("callback must run once on migration", err, calls)
	}
}
