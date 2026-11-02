package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"google.golang.org/grpc/codes"
	"sort"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMFACapabilities(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	supporter, ok := any(c).(interface {
		CheckMFASupport(context.Context) error
		MFASupported() bool
	})
	if !ok {
		t.Fatal("MFA capability missing")
	}
	if err := supporter.CheckMFASupport(context.Background()); err != nil || !supporter.MFASupported() {
		t.Fatalf("MFA support: %v", err)
	}
}

func TestMFARemoteConditionalUpdates(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx := context.Background()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "mfa", Name: "mfa"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Users().Create(ctx, &store.User{TenantID: "mfa", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	a := &store.Authenticator{TenantID: "mfa", UserID: "u", ID: "a", Type: "totp"}
	if err := c.MFA().CreateAuthenticator(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().AcceptTOTPStep(ctx, "mfa", "u", "a", 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().AcceptTOTPStep(ctx, "mfa", "u", "a", 1, time.Now()); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("replay: %v", err)
	}
}

func TestMFACapabilityCompatibility(t *testing.T) {
	ctx := context.Background()
	t.Run("old-plugin", func(t *testing.T) {
		c := serveEventsFaults(t, memory.New(), &eventsFaults{mfaMissing: true})
		if c.MFASupported() {
			t.Fatal("old plugin reports MFA support")
		}
		if _, err := c.MFA().GetGuardian(ctx, "t"); !errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("old plugin: %v", err)
		}
		if err := c.WithTx(ctx, func(tx store.Store) error {
			if tx.(store.MFASupporter).MFASupported() {
				t.Fatal("transaction reports MFA support")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("transient", func(t *testing.T) {
		f := &eventsFaults{}
		c := serveEventsFaults(t, memory.New(), f)
		f.mfaProbe.Store(int32(codes.Unavailable))
		if c.MFASupported() {
			t.Fatal("failed probe reported support")
		}
		if !c.MFASupported() {
			t.Fatal("transient probe was cached")
		}
		f.mfaOperation.Store(int32(codes.Unavailable))
		if _, err := c.MFA().GetGuardian(ctx, "t"); err == nil || errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("transport error: %v", err)
		}
		f.mfaOperation.Store(int32(codes.Unimplemented))
		if _, err := c.MFA().GetGuardian(ctx, "t"); !errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("unknown method: %v", err)
		}
		if c.MFASupported() {
			t.Fatal("unknown method not cached")
		}
		if err := c.CheckMFASupport(ctx); err != nil || !c.MFASupported() {
			t.Fatalf("recovery: %v", err)
		}
	})
}
func TestMFAPrePluginPriorFeatures(t *testing.T) {
	var names []string
	for n := range storetest.Suites {
		if n != "MFA" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	storetest.RunSuites(t, func(t *testing.T) store.Store {
		m := memory.New()
		c := serveEventsFaults(t, m, &eventsFaults{mfaMissing: true})
		if !errors.Is(c.CheckMFASupport(context.Background()), store.ErrMFAUnavailable) {
			t.Fatal("MFA advertised")
		}
		return limitForwarder{c, m}
	}, names...)
}
