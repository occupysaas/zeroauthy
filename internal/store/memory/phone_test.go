package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestPhoneConformance(t *testing.T) {
	storetest.Phone(t, func(*testing.T) store.Store { return memory.New() })
}

func TestPhoneTransactionRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{TenantID: "t", ID: "p", Name: "twilio", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		return store.ErrConflict
	})
	if err == nil {
		t.Fatal("transaction did not fail")
	}
	if l, _ := s.Phone().ListPhoneProviders(ctx, "t"); len(l) != 0 {
		t.Fatalf("rolled-back provider visible: %+v", l)
	}
}
