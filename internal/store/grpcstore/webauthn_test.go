package grpcstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestWebAuthnCapabilityNegotiated(t *testing.T) {
	c := inProcess(t)
	s, ok := any(c).(store.WebAuthnSupporter)
	if !ok {
		t.Fatal("client has no WebAuthn capability probe")
	}
	if err := s.CheckWebAuthnSupport(context.Background()); err != nil || !s.WebAuthnSupported() {
		t.Fatalf("webauthn.v1 not negotiated: %v", err)
	}
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "WebAuthn")
}

func TestOldPluginWebAuthnUnavailable(t *testing.T) {
	ctx := context.Background()
	c := serveEventsFaults(t, memory.New(), &eventsFaults{webauthnMissing: true})
	s := any(c).(store.WebAuthnSupporter)
	if s.WebAuthnSupported() {
		t.Fatal("old plugin reports WebAuthn support")
	}
	if _, err := c.WebAuthn().GetAuthenticatorByCredentialID(ctx, "t", []byte("x")); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("get: %v", err)
	}
	if err := c.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "t"}); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("snooze: %v", err)
	}
	tn := &store.Tenant{ID: "t", Name: "t", DomainRPIDs: map[string]string{"login.t.test": "t.test"}}
	if err := c.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	got, err := c.Tenants().Get(ctx, "t")
	if err != nil || got.DomainRPIDs != nil {
		t.Fatalf("tenant domain RP IDs not dropped: %+v %v", got, err)
	}
	cl := &store.Client{TenantID: "t", ClientID: "c", Name: "c", Mobile: &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "T"}}}
	if err := c.Clients().Create(ctx, cl); err != nil {
		t.Fatal(err)
	}
	if gc, err := c.Clients().Get(ctx, "t", "c"); err != nil || gc.Mobile != nil {
		t.Fatalf("client mobile not dropped: %+v %v", gc, err)
	}
	if err := c.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@t.test"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h", UserID: "auth0|u", AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), CreatedAt: now,
		AuthMethods: []store.AuthMethod{{Name: "passkey", At: now}}}
	if err := c.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if gs, err := c.Sessions().Get(ctx, "t", "s"); err != nil || gs.AuthMethods != nil {
		t.Fatalf("session methods not dropped: %+v %v", gs, err)
	}
	if err := c.Sessions().AddMethod(ctx, "t", "s", store.AuthMethod{Name: "mfa", Type: "otp", At: now}); err != nil {
		t.Fatalf("old plugin append: %v", err)
	}
	if gs, err := c.Sessions().Get(ctx, "t", "s"); err != nil || gs.AuthMethods != nil {
		t.Fatalf("old plugin appended methods: %+v %v", gs, err)
	}
	// MFA keeps working against the old plugin.
	if _, err := c.MFA().ListAuthenticators(ctx, "t", "auth0|u"); err != nil {
		t.Fatalf("MFA list: %v", err)
	}
}

func TestWebAuthnCodecNotLogged(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	challenge := []byte("raw-challenge-bytes-0123456789ab")
	binding := []byte(`{"purpose":"passkey-login","user_handle":"secret-handle-value"}`)
	if err := c.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", ID: "ch", Kind: "webauthn", Challenge: challenge, Binding: binding, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	got, err := c.MFA().GetChallenge(ctx, "a", "ch", time.Now())
	if err != nil || !bytes.Equal(got.Challenge, challenge) || !bytes.Equal(got.Binding, binding) {
		t.Fatalf("challenge round trip: %+v %v", got, err)
	}
	for _, secret := range []string{string(challenge), "secret-handle-value"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log output contains %q", secret)
		}
	}
}
