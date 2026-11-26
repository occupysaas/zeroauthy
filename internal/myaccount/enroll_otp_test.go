package myaccount

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type sentMail struct {
	mu   sync.Mutex
	sent []email.Event
}

func (m *sentMail) Send(_ context.Context, e email.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	return nil
}

func (m *sentMail) lastCode(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no email sent")
	}
	return fmt.Sprint(m.sent[len(m.sent)-1].Variables["code"])
}

type sentPhone struct {
	mu   sync.Mutex
	sent []phone.Message
}

func (p *sentPhone) Working(context.Context, string, phone.Route) (bool, error) { return true, nil }
func (p *sentPhone) DeliveryMethods(context.Context, string, phone.Route) ([]string, error) {
	return []string{"text", "voice"}, nil
}
func (p *sentPhone) Send(_ context.Context, _ string, _ phone.Route, m phone.Message) (phone.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, m)
	return phone.Result{}, nil
}

// withMFA gives e an MFA service with fixture email and phone delivery.
func (e *env) withMFA(t *testing.T) (*sentMail, *sentPhone) {
	t.Helper()
	mail, ph := &sentMail{}, &sentPhone{}
	svc := mfa.NewService(e.st, e.w, mail, nil, e.h.Log, func() time.Time { return e.now })
	svc.Phone = ph
	e.h.MFA = svc
	e.route = e.h.Routes()
	return mail, ph
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(at.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(b[:])
	sum := h.Sum(nil)
	i := int(sum[19] & 15)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[i:i+4])&0x7fffffff)%1000000)
}

func (e *env) start(t *testing.T, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return e.do(t, e.token(t), "POST", "/authentication-methods", body)
}

func (e *env) verify(t *testing.T, id string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return e.do(t, e.token(t), "POST", "/authentication-methods/"+pathID(id)+"/verify", body)
}

func (e *env) method(t *testing.T, id string) *store.Authenticator {
	t.Helper()
	a, err := e.st.MFA().GetAuthenticator(context.Background(), e.tn.ID, e.user.UserID, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnrollTOTP(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	e.guardian(t, "otp")
	rec, out := e.start(t, map[string]any{"type": "totp"})
	if rec.Code != 202 {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	id, _ := out["id"].(string)
	secret, _ := out["manual_input_code"].(string)
	if !strings.HasPrefix(id, "totp|") || secret == "" || !strings.HasPrefix(fmt.Sprint(out["barcode_uri"]), "otpauth://totp/") || out["auth_session"] == nil {
		t.Fatalf("start body %v", out)
	}
	if loc := rec.Header().Get("Location"); loc != "https://"+host+Path+"/authentication-methods/"+pathID(id) {
		t.Errorf("Location %q", loc)
	}
	if strings.Contains(e.logs.String(), secret) {
		t.Error("TOTP secret logged")
	}
	// A wrong code is refused and spends the session; the method stays pending.
	rec, _ = e.verify(t, id, map[string]any{"auth_session": out["auth_session"], "otp_code": "000000"})
	if rec.Code != 400 {
		t.Fatalf("wrong code = %d %s", rec.Code, rec.Body)
	}
	if e.method(t, id).Confirmed {
		t.Fatal("confirmed by a wrong code")
	}
	rec, out = e.start(t, map[string]any{"type": "totp"})
	id, secret = out["id"].(string), out["manual_input_code"].(string)
	code := totpCode(t, secret, e.now)
	rec, got := e.verify(t, id, map[string]any{"auth_session": out["auth_session"], "otp_code": code})
	if rec.Code != 201 || got["id"] != id || got["type"] != "totp" || got["confirmed"] != true {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if !e.method(t, id).Confirmed {
		t.Fatal("not confirmed")
	}
	if strings.Contains(e.logs.String(), code) {
		t.Error("OTP code logged")
	}
	// No recovery code appears behind the user's back.
	all, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, e.user.UserID)
	for _, a := range all {
		if a.Type == "recovery-code" {
			t.Fatal("a recovery code was created by TOTP enrollment")
		}
	}
}

func TestEnrollEmail(t *testing.T) {
	e := newEnv(t)
	mail, _ := e.withMFA(t)
	e.guardian(t, "email")
	// LR42a-8: only the user's verified email.
	if rec, out := e.start(t, map[string]any{"type": "email", "email": "other@acme.test"}); rec.Code != 400 || out["validation_errors"] == nil {
		t.Fatalf("other email = %d %v", rec.Code, out)
	}
	rec, out := e.start(t, map[string]any{"type": "email", "email": "Alice@acme.test"})
	if rec.Code != 202 {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	id := out["id"].(string)
	code := mail.lastCode(t)
	rec, got := e.verify(t, id, map[string]any{"auth_session": out["auth_session"], "otp_code": code})
	if rec.Code != 201 || got["email"] != "alice@acme.test" || got["confirmed"] != true {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(e.logs.String(), code) {
		t.Error("OTP code logged")
	}
}

func TestEnrollPhone(t *testing.T) {
	e := newEnv(t)
	_, ph := e.withMFA(t)
	e.guardian(t, "sms")
	g, _ := e.st.MFA().GetGuardian(context.Background(), e.tn.ID)
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	g.Stored["/guardian/factors/phone/message-types"] = json.RawMessage(`{"message_types":["sms","voice"]}`)
	if err := e.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	rec, out := e.start(t, map[string]any{"type": "phone", "phone_number": "+15555550123", "preferred_authentication_method": "voice"})
	if rec.Code != 202 {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	ph.mu.Lock()
	last := ph.sent[len(ph.sent)-1]
	ph.mu.Unlock()
	if last.DeliveryMethod != "voice" || last.To != "+15555550123" {
		t.Fatalf("sent %+v", last)
	}
	rec, got := e.verify(t, out["id"].(string), map[string]any{"auth_session": out["auth_session"], "otp_code": last.Code})
	if rec.Code != 201 || got["phone_number"] != "+15555550123" || got["preferred_authentication_method"] != "voice" {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.start(t, map[string]any{"type": "phone", "phone_number": "not a number"}); rec.Code != 400 {
		t.Errorf("bad number = %d", rec.Code)
	}
}

func TestEnrollRecoveryCode(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	e.guardian(t, "recovery-code")
	rec, out := e.start(t, map[string]any{"type": "recovery-code"})
	if rec.Code != 202 {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	code, _ := out["recovery_code"].(string)
	id, _ := out["id"].(string)
	if len(code) != 24 || !strings.HasPrefix(id, "recovery-code|") {
		t.Fatalf("start body %v", out)
	}
	rec, got := e.verify(t, id, map[string]any{"auth_session": out["auth_session"]})
	if rec.Code != 201 || got["id"] != id || got["type"] != "recovery-code" {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if a := e.method(t, id); !a.Confirmed || a.CodeHash != secrets.HashToken(code) {
		t.Fatalf("stored %+v", a)
	}
	if strings.Contains(e.logs.String(), code) {
		t.Error("recovery code logged")
	}
	// A second enrollment replaces the code.
	_, out = e.start(t, map[string]any{"type": "recovery-code"})
	if rec, _ := e.verify(t, out["id"].(string), map[string]any{"auth_session": out["auth_session"]}); rec.Code != 201 {
		t.Fatalf("second = %d", rec.Code)
	}
	all, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, e.user.UserID)
	n := 0
	for _, a := range all {
		if a.Type == "recovery-code" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d recovery codes", n)
	}
}

// Y6: a factor the tenant has not enabled is refused.
func TestEnrollDisabledFactor(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	for _, body := range []map[string]any{{"type": "totp"}, {"type": "email", "email": "alice@acme.test"}, {"type": "phone", "phone_number": "+15555550123"}, {"type": "recovery-code"}} {
		rec, out := e.start(t, body)
		if rec.Code != 400 || out["type"] != "factor_not_enabled" {
			t.Errorf("%v = %d %v", body["type"], rec.Code, out)
		}
	}
	for _, body := range []map[string]any{{}, {"type": "carrier-pigeon"}, {"type": "totp", "extra": 1}} {
		if rec, _ := e.start(t, body); rec.Code != 400 {
			t.Errorf("%v = %d", body, rec.Code)
		}
	}
}

// LR42a-2: push notifications are not supported.
func TestEnrollPush(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	e.guardian(t, "push-notification")
	if rec, out := e.start(t, map[string]any{"type": "push-notification"}); rec.Code != 400 || out["type"] != "factor_not_enabled" {
		t.Fatalf("push = %d %v", rec.Code, out)
	}
}

// Review Focus 1: user B cannot finish user A's enrollment, and A still can.
func TestAuthSessionBoundToUser(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	e.guardian(t, "otp")
	bob := newUser(t, e.st, e.tn.ID, "auth0|bob1", "bob@acme.test", e.now)
	_, out := e.start(t, map[string]any{"type": "totp"})
	id, secret := out["id"].(string), out["manual_input_code"].(string)
	code := totpCode(t, secret, e.now)
	rec, _ := e.do(t, e.tokenFor(t, bob.UserID), "POST", "/authentication-methods/"+pathID(id)+"/verify", map[string]any{"auth_session": out["auth_session"], "otp_code": code})
	if rec.Code != 400 && rec.Code != 404 {
		t.Fatalf("bob verifies alice's = %d %s", rec.Code, rec.Body)
	}
	if e.method(t, id).Confirmed {
		t.Fatal("alice's method confirmed by bob")
	}
	// The session must name this method.
	if rec, _ := e.verify(t, "totp|dev_other", map[string]any{"auth_session": out["auth_session"], "otp_code": code}); rec.Code != 400 {
		t.Fatalf("other id = %d", rec.Code)
	}
	if rec, _ := e.verify(t, id, map[string]any{"auth_session": out["auth_session"], "otp_code": code}); rec.Code != 201 {
		t.Fatalf("alice = %d", rec.Code)
	}
}
