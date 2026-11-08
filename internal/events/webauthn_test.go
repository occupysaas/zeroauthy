package events_test

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestWebAuthnSignupDecoratorRollback(t *testing.T) {
	ctx, s := fixture(t)
	first := user("auth0|first")
	first.Identities = []store.Identity{{Provider: "auth0", Connection: "db", UserID: "first"}}
	credential := &store.Authenticator{TenantID: "ten", UserID: first.UserID, ID: "passkey|first", Type: "passkey", CredentialID: []byte("same-key")}
	if err := s.WebAuthn().CreateUserWithPasskey(ctx, first, credential); err != nil {
		t.Fatal(err)
	}
	got := all(t, ctx, s)
	if len(got) != 1 || got[0].Type != "user.created" {
		t.Fatalf("creation events %+v", got)
	}
	second := user("auth0|second")
	second.Identities = []store.Identity{{Provider: "auth0", Connection: "db", UserID: "second"}}
	credential.UserID = second.UserID
	credential.ID = "passkey|second"
	if err := s.WebAuthn().CreateUserWithPasskey(ctx, second, credential); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("credential conflict %v", err)
	}
	if _, err := s.Users().Get(ctx, "ten", second.UserID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("partial user %v", err)
	}
	if got := all(t, ctx, s); len(got) != 1 {
		t.Fatalf("rollback leaked event %+v", got)
	}
}

type unavailableWebAuthn struct{ store.Store }

func (unavailableWebAuthn) CheckWebAuthnSupport(context.Context) error {
	return store.ErrWebAuthnUnavailable
}
func (unavailableWebAuthn) WebAuthnSupported() bool { return false }
func TestWebAuthnDecoratorCapability(t *testing.T) {
	_, s := fixture(t)
	wrapped := events.Wrap(unavailableWebAuthn{s}, events.Config{})
	cap, ok := wrapped.(store.WebAuthnSupporter)
	if !ok || cap.WebAuthnSupported() || !errors.Is(cap.CheckWebAuthnSupport(context.Background()), store.ErrWebAuthnUnavailable) {
		t.Fatal("WebAuthn capability lost")
	}
}
