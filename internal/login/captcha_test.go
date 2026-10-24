package login

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

type captchaStub struct {
	err   error
	calls int
	last  protection.CaptchaChallenge
}

func (c *captchaStub) Verify(_ context.Context, ch protection.CaptchaChallenge, response string) error {
	c.calls++
	c.last = ch
	if c.err != nil {
		return c.err
	}
	if response != "good" {
		return protection.ErrCaptchaInvalid
	}
	return nil
}
func TestCaptchaHostedAndRisk(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "when_risky"
	tn.ProtectionSettings.Bot.BotDetectionLevel = "high"
	tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
	tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	stub := &captchaStub{}
	e.h.Protection = &protection.Service{Store: e.st, Now: fixedNow, CaptchaVerifier: stub}
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	if strings.Contains(page.Body.String(), "js.hcaptcha.com") {
		t.Fatal("script loaded before risk")
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}}
	rec := b.do(t, "POST", "/u/login", form)
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	rec = b.do(t, "GET", "/u/login?state="+state, nil)
	if !strings.Contains(rec.Body.String(), "js.hcaptcha.com") {
		t.Fatal("wrong credentials did not activate challenge")
	}
	form.Set("password", "alice password 1")
	rec = b.do(t, "POST", "/u/login", form)
	if rec.Code != 400 || stub.calls != 0 {
		t.Fatal("missing proof accepted", rec.Code, stub.calls)
	}
	form.Set("h-captcha-response", "good")
	form.Set("provider", "evil")
	form.Set("hostname", "evil")
	rec = b.do(t, "POST", "/u/login", form)
	if rec.Code != 302 || stub.calls != 1 || stub.last.Hostname != "acme.example.test" || stub.last.TransactionID != state || stub.last.ProviderID != "hcaptcha" {
		t.Fatal(rec.Code, stub.last, rec.Body.String())
	}
}
func TestCaptchaHostedSignupAndReset(t *testing.T) {
	for _, kind := range []string{"signup", "reset-send", "reset"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			tn := mustTenant(t, e, "acme")
			tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
			tn.ProtectionSettings.Bot.ChallengePasswordResetPolicy = "always"
			tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
			tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
			if err := e.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			stub := &captchaStub{}
			e.h.Protection = &protection.Service{Store: e.st, Now: fixedNow, CaptchaVerifier: stub}
			b := e.browser("acme.example.test")
			var form url.Values
			var path string
			if kind == "reset" {
				raw := e.issueTicket(t, "alice@acme.test", time.Hour)
				page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
				csrf := csrfField.FindStringSubmatch(page.Body.String())
				if csrf == nil {
					t.Fatal(page.Body.String())
				}
				form = url.Values{"ticket": {raw}, "csrf": {csrf[1]}, "password": {"new password 123"}, "password_confirm": {"new password 123"}}
				path = "/u/reset-password"
			} else {
				_, state, csrf := b.begin(t)
				form = url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"new password 123"}}
				path = "/u/signup"
				if kind == "reset-send" {
					path = "/u/reset-password/request"
					form.Set("email", "alice@acme.test")
				}
			}
			rec := b.do(t, "POST", path, form)
			if rec.Code != 400 || stub.calls != 0 {
				t.Fatal("missing challenge", rec.Code, stub.calls)
			}
			if kind == "reset" {
				tk, err := e.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(form.Get("ticket")))
				if err != nil || tk.UsedAt != nil {
					t.Fatal("ticket consumed", err)
				}
			}
			form.Set("h-captcha-response", "good")
			rec = b.do(t, "POST", path, form)
			want := 200
			if kind == "signup" {
				want = 302
			}
			if rec.Code != want || stub.calls != 1 || stub.last.Flow != kind {
				t.Fatal(rec.Code, stub.last, rec.Body.String())
			}
		})
	}
}
func TestCaptchaContextAndUnavailable(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, _, _ = b.begin(t)
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	stub := &captchaStub{}
	e.h.Protection = &protection.Service{Store: e.st, Now: fixedNow, CaptchaVerifier: stub}
	// Unsupported active provider refuses before password work, but normal CSRF
	// and transaction validation still win over any submitted proof.
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {"forged"}, "csrf": {"forged"}, "h-captcha-response": {"good"}})
	if rec.Code != 400 || stub.calls != 0 {
		t.Fatal(rec.Code, stub.calls)
	}
}

func TestCaptchaUnavailablePreservesLogin(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != 503 || rec.Header().Get("Location") != "" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
func TestCaptchaRiskRefreshUnavailable(t *testing.T) {
	for _, kind := range []string{"login", "signup", "reset"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			tn := mustTenant(t, e, "acme")
			tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "when_risky"
			tn.ProtectionSettings.Bot.ChallengePasswordResetPolicy = "when_risky"
			tn.ProtectionSettings.Bot.BotDetectionLevel = "high"
			if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
			path := "/u/" + kind
			form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "email": {"new@acme.test"}, "password": {"wrong"}}
			if kind == "signup" {
				form.Set("password", "a")
			}
			if kind == "reset" {
				raw := e.issueTicket(t, "alice@acme.test", time.Hour)
				page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
				csrf := csrfField.FindStringSubmatch(page.Body.String())
				if csrf == nil {
					t.Fatal(page.Body.String())
				}
				path = "/u/reset-password"
				form = url.Values{"ticket": {raw}, "csrf": {csrf[1]}, "password": {"a"}, "password_confirm": {"a"}}
			}
			rec := b.do(t, "POST", path, form)
			if rec.Code != 503 || !strings.Contains(rec.Body.String(), "Verification is unavailable") {
				t.Fatal(rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCaptchaProviderUnavailableDoesNotRecordRisk(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
	tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	e.h.Protection = &protection.Service{Store: e.st, Now: fixedNow, CaptchaVerifier: &captchaStub{err: protection.ErrCaptchaUnavailable}}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}, "h-captcha-response": {"good"}})
	if rec.Code != 503 {
		t.Fatal(rec.Code)
	}
	// A direct repository query uses the test browser's address.
	count, err := e.st.Protection().RiskCount(context.Background(), tn.ID, "192.0.2.1", fixedNow())
	if err != nil || count != 0 {
		t.Fatal(count, err)
	}
}
