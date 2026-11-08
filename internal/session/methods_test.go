package session

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSessionMethods(t *testing.T) {
	m, c, tn := setup()
	ctx := context.Background()
	s, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "user", "db", c.t, store.AuthMethod{Name: "passkey"})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddMethod(ctx, s, store.AuthMethod{Name: "mfa", Type: "otp"}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil || len(got.AuthMethods) != 2 || got.AuthMethods[0].Name != "passkey" || got.AuthMethods[0].At.IsZero() || got.AuthMethods[1].Type != "otp" {
		t.Fatalf("methods %+v err %v", got, err)
	}
}
