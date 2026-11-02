package memory_test

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestMFAGuardianDefaults(t *testing.T) {
	s := memory.New()
	got, err := s.MFA().GetGuardian(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Factors) != 8 || len(got.Policies) != 0 {
		t.Fatalf("unexpected defaults: %#v", got)
	}
	for name, enabled := range got.Factors {
		if enabled {
			t.Errorf("%s enabled by default", name)
		}
	}
}

func TestMFAConformance(t *testing.T) {
	storetest.MFA(t, func(*testing.T) store.Store { return memory.New() })
}

func TestMFATransactionRollback(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	sentinel := errors.New("rollback")
	err := s.WithTx(ctx, func(tx store.Store) error {
		g, err := tx.MFA().GetGuardian(ctx, "tenant")
		if err != nil {
			return err
		}
		g.Factors["otp"] = true
		if err := tx.MFA().PutGuardian(ctx, g, 0); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	g, err := s.MFA().GetGuardian(ctx, "tenant")
	if err != nil || g.Factors["otp"] || g.Version != 0 {
		t.Fatalf("rollback: %+v, %v", g, err)
	}
}
