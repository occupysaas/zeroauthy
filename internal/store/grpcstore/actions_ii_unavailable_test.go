package grpcstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Until this adapter supports module pins, it must refuse before reaching storage/RPC.
func TestActionsIITemporaryModuleRefRefusal(t *testing.T) {
	r := clientActions{}
	for name, fn := range map[string]func(context.Context, *store.Action) error{"Create": r.CreateAction, "Update": r.UpdateAction} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatal("module references reached unsupported adapter")
				}
			}()
			err := fn(context.Background(), &store.Action{TenantID: "ii", ID: "x", Name: "x", Trigger: "post-login", Modules: []store.ModuleRef{{ModuleID: "m", VersionID: "v"}}})
			if !errors.Is(err, store.ErrActionsUnavailable) {
				t.Fatal(err)
			}
		})
	}
}
