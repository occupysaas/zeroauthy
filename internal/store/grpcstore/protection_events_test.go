package grpcstore

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestProtectionDeniedKinds(t *testing.T) {
	for _, factory := range []struct {
		name string
		open func(*testing.T) store.Store
	}{{"native", func(*testing.T) store.Store { return memory.New() }}, {"grpc", func(t *testing.T) store.Store { return inProcess(t) }}, {"sqlite-grpc", func(t *testing.T) store.Store { return inProcessSQLite(t) }}} {
		t.Run(factory.name, func(t *testing.T) {
			st := factory.open(t)
			t.Cleanup(func() { _ = st.Close() })
			ctx := context.Background()
			if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			limits := []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: "tenant", Kind: store.ProtectionBruteForce, Identifier: "user"}, Algorithm: "brute-force", Capacity: 1, Lockout: time.Minute}, {Key: store.ProtectionKey{TenantID: "tenant", Kind: store.ProtectionSuspiciousIPLogin, IP: "192.0.2.1"}, Algorithm: "fixed-window", Capacity: 1, Window: time.Minute}}
			allowed, err := st.Protection().Reserve(ctx, limits, now)
			if err != nil || !allowed.Allowed || len(allowed.DeniedKinds) != 0 {
				t.Fatal(allowed, err)
			}
			if err = st.Protection().Complete(ctx, allowed.Receipt, "failure", now); err != nil {
				t.Fatal(err)
			}
			denied, err := st.Protection().Reserve(ctx, limits, now)
			if err != nil || denied.Allowed || !slices.Contains(denied.DeniedKinds, store.ProtectionBruteForce) || !slices.Contains(denied.DeniedKinds, store.ProtectionSuspiciousIPLogin) {
				t.Fatalf("denied=%+v err=%v", denied, err)
			}
		})
	}
}
