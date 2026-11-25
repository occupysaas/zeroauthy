package myaccount

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthSessionSingleUse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := &Caller{TenantID: e.tn.ID, UserID: e.user.UserID, ClientID: "app"}
	raw, err := e.h.newAuthSession(ctx, c, "totp", "totp|dev_1", map[string]string{"k": "v"})
	if err != nil || len(raw) < 32 {
		t.Fatalf("new = %q %v", raw, err)
	}
	s, err := e.h.takeAuthSession(ctx, c, raw, "totp")
	if err != nil || s.MethodID != "totp|dev_1" || string(s.Data) != `{"k":"v"}` {
		t.Fatalf("take = %+v %v", s, err)
	}
	if _, err := e.h.takeAuthSession(ctx, c, raw, "totp"); !errors.Is(err, errAuthSession) {
		t.Fatalf("second take = %v", err)
	}
}

func TestAuthSessionExpires(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := &Caller{TenantID: e.tn.ID, UserID: e.user.UserID, ClientID: "app"}
	raw, _ := e.h.newAuthSession(ctx, c, "email", "email|dev_1", nil)
	e.now = e.now.Add(AuthSessionLifetime + time.Second)
	if _, err := e.h.takeAuthSession(ctx, c, raw, "email"); !errors.Is(err, errAuthSession) {
		t.Fatalf("expired take = %v", err)
	}
	e.now = e.now.Add(-2 * time.Second)
	raw, _ = e.h.newAuthSession(ctx, c, "email", "email|dev_1", nil)
	e.now = e.now.Add(AuthSessionLifetime - time.Second)
	if _, err := e.h.takeAuthSession(ctx, c, raw, "email"); err != nil {
		t.Fatalf("take before expiry = %v", err)
	}
}

// The session is bound to user, application and type; a mismatch does not
// spend it, so the owner can still finish.
func TestAuthSessionBinding(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := &Caller{TenantID: e.tn.ID, UserID: e.user.UserID, ClientID: "app"}
	raw, _ := e.h.newAuthSession(ctx, owner, "totp", "totp|dev_1", nil)
	for name, c := range map[string]*Caller{
		"other user":   {TenantID: e.tn.ID, UserID: "auth0|bob", ClientID: "app"},
		"other client": {TenantID: e.tn.ID, UserID: e.user.UserID, ClientID: "other"},
		"other tenant": {TenantID: "ten_other", UserID: e.user.UserID, ClientID: "app"},
	} {
		if _, err := e.h.takeAuthSession(ctx, c, raw, "totp"); !errors.Is(err, errAuthSession) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.h.takeAuthSession(ctx, owner, raw, "email"); !errors.Is(err, errAuthSession) {
		t.Errorf("other type: %v", err)
	}
	for _, bad := range []string{"", raw + "x", strings.ToUpper(raw), "Fe26.2**05c400ed"} {
		if _, err := e.h.takeAuthSession(ctx, owner, bad, "totp"); !errors.Is(err, errAuthSession) {
			t.Errorf("tampered %q: %v", bad, err)
		}
	}
	if _, err := e.h.takeAuthSession(ctx, owner, raw, "totp"); err != nil {
		t.Fatalf("owner after mismatches = %v", err)
	}
	if strings.Contains(e.logs.String(), raw) {
		t.Error("the auth_session value was logged")
	}
}
