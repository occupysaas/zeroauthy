package mfa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type serviceMail struct {
	messages []email.Message
	err      error
}

func (m *serviceMail) Send(_ context.Context, msg email.Message) error {
	m.messages = append(m.messages, msg)
	return m.err
}

type serviceEvents struct {
	mu     sync.Mutex
	events []logs.Event
}

func (r *serviceEvents) Record(_ context.Context, e logs.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *serviceEvents) count(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Type == kind {
			n++
		}
	}
	return n
}

type serviceFixture struct {
	ctx    context.Context
	st     *memory.Store
	w      keys.Wrapper
	svc    *Service
	mail   *serviceMail
	events *serviceEvents
	now    time.Time
	output bytes.Buffer
	email  *email.Service
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := &serviceFixture{ctx: context.Background(), now: time.Unix(1800000000, 0).UTC(), st: memory.New(), mail: &serviceMail{}, events: &serviceEvents{}}
	t.Cleanup(func() { _ = f.st.Close() })
	for _, id := range []string{"tenant", "other"} {
		if err := f.st.Tenants().Create(f.ctx, &store.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []store.User{{TenantID: "tenant", UserID: "user", Email: "one@example.test", EmailVerified: true}, {TenantID: "tenant", UserID: "other", Email: "two@example.test", EmailVerified: true}, {TenantID: "other", UserID: "user", Email: "three@example.test", EmailVerified: true}} {
		if err := f.st.Users().Create(f.ctx, &u); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.w, err = keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := email.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	f.email = &email.Service{Store: f.st, Wrapper: f.w, Renderer: renderer, Fallback: f.mail, DefaultFrom: "auth@example.test", Now: func() time.Time { return f.now }}
	f.svc = NewService(f.st, f.w, f.email, f.st.Protection(), slog.New(slog.NewJSONHandler(&f.output, nil)), func() time.Time { return f.now })
	f.svc.Recorder = f.events
	g, err := f.st.MFA().GetGuardian(f.ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	g.Factors["otp"] = true
	g.Factors["email"] = true
	g.Factors["recovery-code"] = true
	if err = f.st.MFA().PutGuardian(f.ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	return f
}
func codeAt(t *testing.T, secret string, at time.Time) string {
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
func (f *serviceFixture) enroll(t *testing.T) (*Enrollment, *Confirmed) {
	t.Helper()
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)})
	if err != nil {
		t.Fatal(err)
	}
	return e, c
}
func TestEnrollTOTPThenVerify(t *testing.T) {
	f := newServiceFixture(t)
	e, c := f.enroll(t)
	if !regexp.MustCompile(`^[A-Z0-9]{24}$`).MatchString(c.RecoveryCode) {
		t.Fatal("first enrollment missing recovery code")
	}
	a, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", e.AuthenticatorID)
	if err != nil || !a.Confirmed || bytes.Contains(a.SealedSecret, []byte(e.Secret)) {
		t.Fatal("TOTP not confirmed and sealed")
	}
	for _, aad := range [][]byte{[]byte("other"), totpAAD("other", "user", a.ID), totpAAD("tenant", "other", a.ID), totpAAD("tenant", "user", "other")} {
		if _, err = f.w.Unwrap(a.SealedSecret, aad); err == nil {
			t.Fatal("unbound TOTP ciphertext")
		}
	}
	if _, err = f.svc.BeginChallenge(f.ctx, "other", "user", a.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant challenge=%v", err)
	}
	ch, err := f.svc.BeginChallenge(f.ctx, "tenant", "user", a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: codeAt(t, e.Secret, f.now)}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay=%v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	if err = f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: codeAt(t, e.Secret, f.now)}); err != nil {
		t.Fatal(err)
	}
	if err = f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: codeAt(t, e.Secret, f.now)}); err == nil {
		t.Fatal("consumed challenge accepted")
	}
	_, second := f.enroll(t)
	if second.RecoveryCode != "" {
		t.Fatal("second enrollment replaced recovery code")
	}
	if f.events.count("gd_start_enroll") != 2 || f.events.count("gd_enrollment_complete") != 2 || f.events.count("gd_auth_succeed") != 1 {
		t.Fatal("enrollment/auth events missing")
	}
}
func TestEmailChallengeSendsTemplate(t *testing.T) {
	f := newServiceFixture(t)
	if err := f.st.EmailTemplates().Put(f.ctx, &store.EmailTemplate{TenantID: "tenant", Name: "mfa_oob_code", Fields: map[string]any{"body": "<p>Custom code: {{ code }}; {{ expires_in }} seconds</p>", "subject": "MFA"}}, 0); err != nil {
		t.Fatal(err)
	}
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mail.messages) != 1 {
		t.Fatal("email not delivered")
	}
	msg := f.mail.messages[0]
	code := regexp.MustCompile(`[0-9]{6}`).FindString(msg.Text)
	if msg.Type != "mfa_oob_code" || msg.To != "one@example.test" || !strings.Contains(msg.Text, "Custom code:") || !strings.Contains(msg.Text, "300 seconds") || code == "" {
		t.Fatalf("wrong delivery: %+v", msg)
	}
	saved, err := f.st.MFA().GetChallenge(f.ctx, "tenant", secrets.HashToken(e.ChallengeID), f.now)
	if err != nil || saved.CodeHash != secrets.HashToken(code) || !saved.ExpiresAt.Equal(f.now.Add(5*time.Minute)) {
		t.Fatal("challenge hash/expiry incorrect")
	}
	c, err := f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: code})
	if err != nil || c.RecoveryCode == "" {
		t.Fatalf("confirm email: %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	ch, err := f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
	if err != nil {
		t.Fatal(err)
	}
	code = regexp.MustCompile(`[0-9]{6}`).FindString(f.mail.messages[1].Text)
	if err = f.svc.Verify(f.ctx, "tenant", "other", ch, Proof{Code: code}); err == nil {
		t.Fatal("other user challenge accepted")
	}
	f.now = f.now.Add(5 * time.Minute)
	if err = f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: code}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry=%v", err)
	}
}
func TestEmailRequiresVerified(t *testing.T) {
	f := newServiceFixture(t)
	u, _ := f.st.Users().Get(f.ctx, "tenant", "user")
	u.EmailVerified = false
	if err := f.st.Users().Update(f.ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", ""); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("unverified=%v", err)
	}
	if len(f.mail.messages) != 0 {
		t.Fatal("unverified email delivered")
	}
	u.EmailVerified = true
	_ = f.st.Users().Update(f.ctx, u)
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", "")
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "new@example.test"
	_ = f.st.Users().Update(f.ctx, u)
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: regexp.MustCompile(`[0-9]{6}`).FindString(f.mail.messages[0].Text)}); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("changed ownership=%v", err)
	}
}
func TestThrottleTenFailures(t *testing.T) {
	f := newServiceFixture(t)
	e, _ := f.enroll(t)
	f.now = f.now.Add(30 * time.Second)
	ch, _ := f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
	good := codeAt(t, e.Secret, f.now)
	for i := 0; i < 10; i++ {
		if err := f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: "bad"}); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("failure %d=%v", i+1, err)
		}
	}
	// Another service instance observes the same persisted budget.
	other := NewService(f.st, f.w, f.email, f.st.Protection(), nil, func() time.Time { return f.now })
	other.Recorder = f.events
	for i := 0; i < 3; i++ {
		if err := other.Verify(f.ctx, "tenant", "user", ch, Proof{Code: good}); !errors.Is(err, ErrThrottled) {
			t.Fatalf("blocked=%v", err)
		}
	}
	if f.events.count("gd_otp_rate_limit_exceed") != 1 {
		t.Fatal("rate event must be emitted once")
	}
	f.now = f.now.Add(15 * time.Minute)
	ch, _ = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
	for i := 0; i < 9; i++ {
		_ = other.Verify(f.ctx, "tenant", "user", ch, Proof{Code: "bad"})
	}
	if err := other.Verify(f.ctx, "tenant", "user", ch, Proof{Code: codeAt(t, e.Secret, f.now)}); err != nil {
		t.Fatalf("success=%v", err)
	}
	ch, _ = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
	for i := 0; i < 10; i++ {
		if err := f.svc.Verify(f.ctx, "tenant", "user", ch, Proof{Code: "bad"}); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("reset failure %d=%v", i, err)
		}
	}
}
func TestEmailSendLimit(t *testing.T) {
	f := newServiceFixture(t)
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mail.messages) != 1 || !strings.Contains(f.mail.messages[0].Text, "5 minutes") {
		t.Fatal("default MFA template absent")
	}
	if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); !errors.Is(err, ErrThrottled) {
		t.Fatalf("resend=%v", err)
	}
	for i := 1; i < 5; i++ {
		f.now = f.now.Add(30 * time.Second)
		if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); err != nil {
			t.Fatal(err)
		}
	}
	f.now = f.now.Add(30 * time.Second)
	if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); !errors.Is(err, ErrThrottled) {
		t.Fatalf("sixth=%v", err)
	}
	if len(f.mail.messages) != 5 {
		t.Fatalf("sends=%d", len(f.mail.messages))
	}
	f.now = f.now.Add(15 * time.Minute)
	if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); err != nil {
		t.Fatal(err)
	}
}
func TestRecoverReplacesCode(t *testing.T) {
	f := newServiceFixture(t)
	_, c := f.enroll(t)
	next, err := f.svc.Recover(f.ctx, "tenant", "user", strings.ToLower(c.RecoveryCode))
	if err != nil || next == c.RecoveryCode || !regexp.MustCompile(`^[A-Z0-9]{24}$`).MatchString(next) {
		t.Fatalf("rotation=%v", err)
	}
	if _, err = f.svc.Recover(f.ctx, "tenant", "user", c.RecoveryCode); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("old recovery=%v", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if _, err := f.svc.Recover(f.ctx, "tenant", "user", next); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent recovery successes=%d", successes)
	}
	if f.events.count("gd_recovery_succeed") != 2 {
		t.Fatal("recovery success event missing")
	}
}
func TestWebAuthnFactorNeverOffered(t *testing.T) {
	f := newServiceFixture(t)
	for _, kind := range []string{"webauthn-roaming", "webauthn-platform", "push-notification", "sms", "voice", "duo"} {
		settings, err := f.st.MFA().GetGuardian(f.ctx, "tenant")
		if err != nil {
			t.Fatal(err)
		}
		settings.Factors[kind] = true
		if err = f.st.MFA().PutGuardian(f.ctx, settings, settings.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", kind, ""); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("%s enrollment=%v", kind, err)
		}
		a := &store.Authenticator{TenantID: "tenant", UserID: "user", ID: NewMethodID(kind), Type: kind, Confirmed: true}
		if err := f.st.MFA().CreateAuthenticator(f.ctx, a); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.BeginChallenge(f.ctx, "tenant", "user", a.ID, ""); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("%s challenge=%v", kind, err)
		}
	}
	if _, err := f.svc.BeginChallenge(f.ctx, "other", "user", "totp|dev_missing", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross tenant=%v", err)
	}
}
func TestRecoveryCodeNotOnlyFactor(t *testing.T) {
	f := newServiceFixture(t)
	if _, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "recovery-code", ""); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("recovery enrollment=%v", err)
	}
	_ = f.st.MFA().ReplaceRecoveryCode(f.ctx, "tenant", "user", "", secrets.HashToken("RECOVERY"), f.now)
	if _, err := f.svc.Recover(f.ctx, "tenant", "user", "RECOVERY"); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("only recovery=%v", err)
	}
}
func TestNoSecretsInLogs(t *testing.T) {
	f := newServiceFixture(t)
	e, c := f.enroll(t)
	code := codeAt(t, e.Secret, f.now)
	_ = f.svc.Verify(f.ctx, "tenant", "user", &Challenge{ID: "SENTINEL_CHALLENGE_BYTES", AuthenticatorID: e.AuthenticatorID}, Proof{Code: code})
	_, _ = f.svc.Recover(f.ctx, "tenant", "user", c.RecoveryCode)
	e2, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", "")
	if err != nil {
		t.Fatal(err)
	}
	emailCode := regexp.MustCompile(`[0-9]{6}`).FindString(f.mail.messages[0].Text)
	data, _ := json.Marshal(f.events.events)
	combined := string(data) + f.output.String()
	for _, secret := range []string{e.Secret, code, c.RecoveryCode, emailCode, e2.ChallengeID, "SENTINEL_CHALLENGE_BYTES"} {
		if strings.Contains(combined, secret) {
			t.Fatal("secret appeared in logs")
		}
	}
	if len(f.events.events) == 0 {
		t.Fatal("events silently suppressed")
	}
	for _, name := range []string{"mfa_code", "oob_code", "challenge", "enrollment_ticket", "remember_browser_cookie"} {
		if !logscrub.SensitiveKey(name) {
			t.Errorf("unprotected field %s", name)
		}
	}
}

func TestEmailFiveAttemptsAndBinding(t *testing.T) {
	f := newServiceFixture(t)
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", "")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`[0-9]{6}`).FindString(f.mail.messages[0].Text)
	forged := *e
	forged.Factor = "otp"
	forged.Secret = "ATTACKER_SECRET"
	for i := 0; i < 5; i++ {
		if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", &forged, Proof{Code: "bad"}); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d=%v", i, err)
		}
	}
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: code}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("exhausted accepted: %v", err)
	}
	a, _ := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", e.AuthenticatorID)
	if a.Confirmed {
		t.Fatal("exhausted enrollment confirmed")
	}
	ch, err := f.st.MFA().GetChallenge(f.ctx, "tenant", secrets.HashToken(e.ChallengeID), f.now)
	if err != nil || ch.Attempts != 5 {
		t.Fatal("challenge attempt budget changed")
	}
	f.now = f.now.Add(30 * time.Second)
	c, err := f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
	if err != nil {
		t.Fatal(err)
	}
	e.ChallengeID = c.ID
	code = regexp.MustCompile(`[0-9]{6}`).FindString(f.mail.messages[1].Text)
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: code}); err != nil {
		t.Fatal(err)
	}
}
func TestEnrollConcurrentFirstRecoveryAndTOTPReplay(t *testing.T) {
	f := newServiceFixture(t)
	es := make([]*Enrollment, 2)
	for i := range es {
		var err error
		es[i], err = f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	recoveries := 0
	successes := 0
	for _, e := range es {
		wg.Go(func() {
			c, err := f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Error(err)
			} else {
				successes++
				if c.RecoveryCode != "" {
					recoveries++
				}
			}
		})
	}
	wg.Wait()
	if successes != 2 || recoveries != 1 {
		t.Fatalf("confirmations=%d recovery displays=%d", successes, recoveries)
	}
	f.now = f.now.Add(30 * time.Second)
	chs := make([]*Challenge, 8)
	for i := range chs {
		var err error
		chs[i], err = f.svc.BeginChallenge(f.ctx, "tenant", "user", es[0].AuthenticatorID, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	successes = 0
	code := codeAt(t, es[0].Secret, f.now)
	for _, c := range chs {
		wg.Go(func() {
			if err := f.svc.Verify(f.ctx, "tenant", "user", c, Proof{Code: code}); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("TOTP simultaneous successes=%d", successes)
	}
}
func TestEmailDeliveryFailureCleansEnrollment(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			f := newServiceFixture(t)
			f.mail.err = errors.New("SENTINEL_PRIVATE_PROVIDER_ERROR")
			if disabled {
				if err := f.st.EmailTemplates().Put(f.ctx, &store.EmailTemplate{TenantID: "tenant", Name: "mfa_oob_code", Fields: map[string]any{"enabled": false}}, 0); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "email", ""); !errors.Is(err, ErrEmailDelivery) || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("delivery=%v", err)
			}
			as, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "user")
			if len(as) != 0 {
				t.Fatal("failed delivery retained enrollment")
			}
			if f.events.count("gd_send_email") != 0 || f.events.count("gd_start_enroll_failed") != 1 {
				t.Fatal("delivery event incorrect")
			}
		})
	}
}
func TestUnenrollLogsAndInvalidatesRemember(t *testing.T) {
	f := newServiceFixture(t)
	e, _ := f.enroll(t)
	if err := f.svc.Unenroll(f.ctx, "tenant", "other", e.AuthenticatorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other user deletion=%v", err)
	}
	if err := f.svc.Unenroll(f.ctx, "tenant", "user", e.AuthenticatorID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", e.AuthenticatorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted=%v", err)
	}
	u, _ := f.st.Users().Get(f.ctx, "tenant", "user")
	if u.RememberBrowserEpoch != 1 || f.events.count("gd_unenroll") != 1 {
		t.Fatal("unenroll side effects missing")
	}
}

func TestNoSecretsInEnrichedRecorder(t *testing.T) {
	f := newServiceFixture(t)
	recorder := logs.NewRecorder(f.st, logs.Config{Now: func() time.Time { return f.now }}, slog.New(slog.NewJSONHandler(&f.output, nil)))
	f.svc.Recorder = recorder
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	code := codeAt(t, e.Secret, f.now)
	ctx := logs.WithEvent(f.ctx, logs.Event{UserName: e.Secret + " " + code, ClientID: "public-client"})
	c, err := f.svc.ConfirmEnroll(ctx, "tenant", "user", e, Proof{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	ctx = logs.WithEvent(f.ctx, logs.Event{UserName: c.RecoveryCode})
	if _, err = f.svc.Recover(ctx, "tenant", "user", c.RecoveryCode); err != nil {
		t.Fatal(err)
	}
	if err = recorder.Flush(f.ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.st.Logs().SearchLogs(f.ctx, "tenant", nil, store.LogPage{PerPage: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("recorded events=%d", len(rows))
	}
	var raw []byte
	for _, row := range rows {
		raw = append(raw, row.Body...)
	}
	for _, secret := range []string{e.Secret, code, c.RecoveryCode} {
		if strings.Contains(string(raw)+f.output.String(), secret) {
			t.Fatal("MFA credential leaked through recorder enrichment")
		}
	}
}

// unavailableMFALogs forces the real recorder's slog fallback, so the same
// request-mask guarantee is checked at both persisted and operational sinks.
type unavailableMFALogs struct{ store.Store }

func (s unavailableMFALogs) Logs() store.Logs { return store.UnimplementedLogs{} }

func TestNoSecretsIncomingChallengeFreshContext(t *testing.T) {
	for _, sink := range []string{"store", "slog"} {
		for _, operation := range []string{"confirm", "verify"} {
			for _, valid := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/success=%t", sink, operation, valid), func(t *testing.T) {
					f := newServiceFixture(t)
					var e *Enrollment
					var ch *Challenge
					var err error
					if operation == "confirm" {
						e, err = f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
						if err != nil {
							t.Fatal(err)
						}
						ch = &Challenge{ID: e.ChallengeID, AuthenticatorID: e.AuthenticatorID}
					} else {
						e, _ = f.enroll(t)
						f.now = f.now.Add(30 * time.Second)
						ch, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "")
						if err != nil {
							t.Fatal(err)
						}
					}
					var recorderStore store.Store = f.st
					if sink == "slog" {
						recorderStore = unavailableMFALogs{Store: f.st}
					}
					recorder := logs.NewRecorder(recorderStore, logs.Config{Now: func() time.Time { return f.now }}, slog.New(slog.NewJSONHandler(&f.output, nil)))
					f.svc.Recorder = recorder
					// Deliberately separate from the context that generated the handle.
					fresh := logs.WithEvent(context.Background(), logs.Event{UserName: "incoming=" + ch.ID, UserAgent: "challenge=" + ch.ID})
					code := "bad"
					if valid {
						code = codeAt(t, e.Secret, f.now)
					}
					if operation == "confirm" {
						_, err = f.svc.ConfirmEnroll(fresh, "tenant", "user", e, Proof{Code: code})
					} else {
						err = f.svc.Verify(fresh, "tenant", "user", ch, Proof{Code: code})
					}
					if valid && err != nil || !valid && !errors.Is(err, ErrInvalidCode) {
						t.Fatalf("proof result=%v", err)
					}
					if err = recorder.Flush(context.Background()); err != nil {
						t.Fatal(err)
					}
					var output string
					if sink == "store" {
						rows, _, readErr := f.st.Logs().SearchLogs(context.Background(), "tenant", nil, store.LogPage{PerPage: 100})
						if readErr != nil {
							t.Fatal(readErr)
						}
						if len(rows) != 1 {
							t.Fatalf("recorded events=%d", len(rows))
						}
						output = string(rows[0].Body)
					} else {
						output = f.output.String()
						if output == "" {
							t.Fatal("slog fallback did not record outcome")
						}
					}
					expected := "gd_auth_failed"
					if operation == "confirm" {
						expected = "gd_start_enroll_failed"
					}
					if valid {
						expected = "gd_auth_succeed"
						if operation == "confirm" {
							expected = "gd_enrollment_complete"
						}
					}
					if strings.Contains(output, ch.ID) {
						t.Fatal("incoming challenge handle leaked into enriched outcome")
					}
					if !strings.Contains(output, expected) || !strings.Contains(output, "incoming=") || !strings.Contains(output, logscrub.Marker) {
						t.Fatal("outcome or enriched scrubbed attribution missing")
					}
				})
			}
		}
	}
}

func TestNilEnrollmentAndChallengeProof(t *testing.T) {
	f := newServiceFixture(t)
	if _, err := f.svc.ConfirmEnroll(context.Background(), "tenant", "user", nil, Proof{Code: "bad"}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("nil enrollment=%v", err)
	}
	if err := f.svc.Verify(context.Background(), "tenant", "user", nil, Proof{Code: "bad"}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("nil challenge=%v", err)
	}
}

func TestEnrollNewFactorConcurrent(t *testing.T) {
	f := newServiceFixture(t)
	svc := f.svc.WithNewFactorEnrollment()
	a, err := svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make(chan error, 2)
	for _, e := range []*Enrollment{a, b} {
		go func(e *Enrollment) {
			_, err := svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)})
			outcomes <- err
		}(e)
	}
	successes := 0
	for range 2 {
		err := <-outcomes
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("same-type Action enroll successes=%d", successes)
	}
	if _, err = svc.BeginEnroll(f.ctx, "tenant", "user", "otp", ""); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("same-type association %v", err)
	}
	// Existing ticket-purpose callers retain allow-multiple behavior.
	extra, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", extra, Proof{Code: codeAt(t, extra.Secret, f.now)}); err != nil {
		t.Fatalf("ordinary explicit multiple enrollment %v", err)
	}
}
