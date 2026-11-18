package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type verifyPhoneProvider struct {
	deliveries []phone.ActionInput
	fail       bool
}

func (p *verifyPhoneProvider) PhoneActionBound(context.Context, string, string) (bool, error) {
	return true, nil
}

func (p *verifyPhoneProvider) RunPhoneAction(_ context.Context, _ string, in phone.ActionInput) error {
	p.deliveries = append(p.deliveries, in)
	if p.fail {
		return errors.New("fixture provider error with code " + in.Message.Code)
	}
	return nil
}

func TestVerifyPhoneNumber(t *testing.T) {
	t.Run("memory", func(t *testing.T) { testVerifyPhoneNumber(t, memory.New()) })
	t.Run("SQLite", func(t *testing.T) {
		testVerifyPhoneNumber(t, openSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db")))
	})
}

func testVerifyPhoneNumber(t *testing.T, st store.Store) {
	t.Helper()
	const (
		database = "Username-Password-Authentication"
		number   = "+14155550100"
		next     = "+14155550101"
	)
	ctx := t.Context()
	provider := &verifyPhoneProvider{}
	h, st := newMgmtEnvOn(t, st, usersSeed, func(d *Deps) {
		d.Phone = &phone.Dispatcher{Store: d.Store, Wrapper: d.Wrapper, Actions: provider}
	})
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	tn.SettingsExtra["phone_consolidated_experience"] = true
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	conn, err := st.Connections().GetByName(ctx, tn.ID, database)
	if err != nil {
		t.Fatal(err)
	}
	conn.Extra = map[string]any{"attributes": map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}}}}
	if err := st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err := st.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{
		TenantID: tn.ID, ID: "pro_verify", Name: "custom", Configuration: json.RawMessage(`{"delivery_methods":["text"]}`),
	}); err != nil {
		t.Fatal(err)
	}

	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "users", "users-s3cret")
	ro := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	w, body := sendJSON(h, http.MethodPost, usersBase, admin, map[string]any{
		"connection": database, "user_id": "verify-user", "email": "primary@example.test", "password": "first horse 1",
		"phone_number": number, "phone_verified": true, "verify_email": false,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create user = %d %s", w.Code, w.Body)
	}
	uid := body["user_id"].(string)
	path := usersBase + "/" + url.PathEscape(uid)
	verify := map[string]any{"verify_phone_number": true}
	for _, refusal := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {ro, http.StatusForbidden}} {
		w, _ := sendJSON(h, http.MethodPatch, path, refusal.token, verify)
		if w.Code != refusal.want {
			t.Errorf("scope refusal = %d %s, want %d", w.Code, w.Body, refusal.want)
		}
	}

	before, err := st.Users().Get(ctx, tn.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	w, body = sendJSON(h, http.MethodPatch, path, admin, map[string]any{"verify_phone_number": false})
	if w.Code != http.StatusOK || body["phone_verified"] != true || len(provider.deliveries) != 0 {
		t.Fatalf("verify_phone_number false = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
	after, err := st.Users().Get(ctx, tn.ID, uid)
	if err != nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("false flag changed the profile timestamp: %v", err)
	}
	w, body = sendJSON(h, http.MethodPatch, path, admin, map[string]any{"phone_number": next, "verify_phone_number": true})
	if w.Code != http.StatusOK || body["phone_number"] != next || body["phone_verified"] != false || len(provider.deliveries) != 1 {
		t.Fatalf("verify_phone_number true = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
	in := provider.deliveries[0]
	code := in.Message.Code
	if in.Message.To != next || in.Message.DeliveryMethod != "text" || in.MessageType != "otp_verify" ||
		in.Route.Purpose != "verify" || in.Route.ConnectionID != conn.ID || in.Message.UserID != uid ||
		!regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) || !strings.Contains(in.Message.Body, code) {
		t.Error("provider did not receive the Plan 34 verification message for the updated user")
	}
	if strings.Contains(strings.ReplaceAll(w.Body.String(), next, ""), code) || body["verify_phone_number"] != nil {
		t.Error("PATCH response exposed verification data")
	}
	hash := secrets.HashToken(code)
	for _, kind := range []string{"phone-signup", "phone-reset", "code"} {
		if _, err := st.Phone().ConsumePasswordlessCode(ctx, tn.ID, conn.ID, next, kind, hash, 3, time.Now()); !errors.Is(err, store.ErrPrecondition) {
			t.Errorf("verification code accepted for %q: %v", kind, err)
		}
	}
	if c, err := st.Phone().ConsumePasswordlessCode(ctx, tn.ID, conn.ID, next, "phone-verify", hash, 3, time.Now()); err != nil ||
		c.ExpiresAt.Sub(c.CreatedAt) != 5*time.Minute || c.CodeHash == code {
		t.Errorf("verification code was not stored with its own scope, hash and lifetime: %v", err)
	}

	w, _ = sendJSON(h, http.MethodPatch, path, admin, map[string]any{"phone_number": nil, "verify_phone_number": true})
	if w.Code != http.StatusBadRequest || len(provider.deliveries) != 1 {
		t.Fatalf("clear and verify = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
	w, body = sendJSON(h, http.MethodGet, path, admin, nil)
	if w.Code != http.StatusOK || body["phone_number"] != next {
		t.Fatalf("refused clear changed phone = %d %s", w.Code, w.Body)
	}

	tn.SettingsExtra["country_codes"] = map[string]any{"mode": "allow", "list": []string{"GB"}}
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	w, _ = sendJSON(h, http.MethodPatch, path, admin, verify)
	if w.Code != http.StatusBadRequest || len(provider.deliveries) != 1 {
		t.Fatalf("country restriction = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
	delete(tn.SettingsExtra, "country_codes")
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}

	provider.fail = true
	w, _ = sendJSON(h, http.MethodPatch, path, admin, map[string]any{"name": "Committed Before Delivery", "verify_phone_number": true})
	if w.Code != http.StatusServiceUnavailable || len(provider.deliveries) != 2 {
		t.Fatalf("provider failure = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
	if strings.Contains(w.Body.String(), provider.deliveries[1].Message.Code) || strings.Contains(w.Body.String(), "fixture provider error") {
		t.Error("provider failure exposed delivery details")
	}
	provider.fail = false
	w, body = sendJSON(h, http.MethodGet, path, admin, nil)
	if w.Code != http.StatusOK || body["name"] != "Committed Before Delivery" || body["phone_verified"] != false {
		t.Fatalf("profile after delivery failure = %d %s", w.Code, w.Body)
	}

	for i := 2; i < 10; i++ {
		w, _ := sendJSON(h, http.MethodPatch, path, admin, verify)
		if w.Code != http.StatusOK {
			t.Fatalf("send %d = %d %s", i+1, w.Code, w.Body)
		}
	}
	w, _ = sendJSON(h, http.MethodPatch, path, admin, verify)
	if w.Code != http.StatusTooManyRequests || len(provider.deliveries) != 10 {
		t.Fatalf("send limit = %d %s; %d sends", w.Code, w.Body, len(provider.deliveries))
	}
}
