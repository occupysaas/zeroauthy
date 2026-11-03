package grpcstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

type phoneSupport interface {
	CheckPhoneSupport(context.Context) error
	PhoneSupported() bool
}

func TestPhoneCapabilityNegotiated(t *testing.T) {
	c := inProcess(t)
	s, ok := any(c).(phoneSupport)
	if !ok {
		t.Fatal("client has no phone capability probe")
	}
	if err := s.CheckPhoneSupport(context.Background()); err != nil || !s.PhoneSupported() {
		t.Fatalf("phone.v1 not negotiated: %v", err)
	}
	// The storetest phone suite passes over gRPC.
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "Phone")
}

func TestOldPluginPhoneUnavailable(t *testing.T) {
	ctx := context.Background()
	c := serveEventsFaults(t, memory.New(), &eventsFaults{phoneMissing: true})
	s, ok := any(c).(phoneSupport)
	if !ok {
		t.Fatal("client has no phone capability probe")
	}
	if s.PhoneSupported() {
		t.Fatal("old plugin reports phone support")
	}
	if err := s.CheckPhoneSupport(ctx); !errors.Is(err, store.ErrPhoneUnavailable) {
		t.Fatalf("probe: %v", err)
	}
	if _, err := c.Phone().ListPhoneProviders(ctx, "t"); !errors.Is(err, store.ErrPhoneUnavailable) {
		t.Fatalf("list: %v", err)
	}
	if _, err := c.Phone().ConsumePasswordlessCode(ctx, "t", "c", "i", "code", "h", 3, time.Now()); !errors.Is(err, store.ErrPhoneUnavailable) {
		t.Fatalf("consume: %v", err)
	}
	// A transaction handle shares the latched answer.
	if err := c.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Phone().FindUsersByPhone(ctx, "t", "c", "+14155550100"); !errors.Is(err, store.ErrPhoneUnavailable) {
			t.Fatalf("tx find: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Every other feature keeps working against the old plugin.
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
}

// Sealed credentials, request blobs and code hashes cross the wire byte for
// byte, and none of it reaches the log output.
func TestPhoneCodecOpaqueAndNotLogged(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	sealed := []byte{0, 1, 2, 0xff, 0xfe, 's', 'e', 'c', 'r', 'e', 't', '-', 'S', 'E', 'A', 'L'}
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := &store.PhoneProvider{TenantID: "a", ID: "p", Name: "twilio", Configuration: json.RawMessage(`{"sid":"AC1"}`), SealedCredentials: sealed, CreatedAt: now, UpdatedAt: now}
	if err := c.Phone().CreatePhoneProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := c.Phone().GetPhoneProvider(ctx, "a", "p")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.SealedCredentials, sealed) || string(got.Configuration) != `{"sid":"AC1"}` || !got.CreatedAt.Equal(now) {
		t.Fatalf("provider changed on the wire: %+v", got)
	}
	req := json.RawMessage(`{"sealed":"REQUEST-BLOB"}`)
	pc := &store.PasswordlessCode{TenantID: "a", ConnectionID: "sms", Identifier: "+14155550100", ClientID: "c", Kind: "link", CodeHash: "HASH-abc123", Request: req, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := c.Phone().PutPasswordlessCode(ctx, pc); err != nil {
		t.Fatal(err)
	}
	link, err := c.Phone().PeekPasswordlessLink(ctx, "a", "HASH-abc123", now)
	if err != nil {
		t.Fatal(err)
	}
	if link.CodeHash != "HASH-abc123" || string(link.Request) != string(req) || link.Identifier != "+14155550100" || link.Attempts != 0 {
		t.Fatalf("code changed on the wire: %+v", link)
	}
	if n, err := c.Phone().FailPasswordlessCode(ctx, "a", "sms", "+14155550100", "link", now); err != nil || n != 1 {
		t.Fatalf("fail = %d, %v", n, err)
	}
	if _, err := c.Phone().ConsumePasswordlessCode(ctx, "a", "sms", "+14155550100", "link", "wrong", 5, now); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("wrong hash: %v", err)
	}
	if _, err := c.Phone().ConsumePasswordlessCode(ctx, "a", "sms", "+14155550100", "link", "HASH-abc123", 5, now); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-SEAL", "REQUEST-BLOB", "HASH-abc123", "+14155550100"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log output contains %q:\n%s", secret, logs.String())
		}
	}
}

func TestUserPhoneNormalizedRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	u := &store.User{TenantID: "a", UserID: "u", PhoneNumber: "+1 415 555 0100", PhoneNormalized: "+14155550100"}
	if err := c.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := c.Users().Get(ctx, "a", "u")
	if err != nil || got.PhoneNormalized != "+14155550100" {
		t.Fatalf("user = %+v, %v", got, err)
	}
}
