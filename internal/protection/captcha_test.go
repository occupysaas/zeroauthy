package protection

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func captchaFixture(t *testing.T, provider string, transport http.RoundTripper) (*Service, CaptchaChallenge) {
	t.Helper()
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := protectionrules.Defaults()
	values := map[string]any{"site_key": "site", "secret": "secret"}
	if provider == "recaptcha_enterprise" {
		values = map[string]any{"site_key": "site", "api_key": "secret", "project_id": "project"}
	}
	p, err = keys.PatchCAPTCHA(w, "t", p, map[string]any{"active_provider_id": provider, provider: values})
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	if err := st.Tenants().Create(context.Background(), &store.Tenant{ID: "t", Name: "t", ProtectionSettings: p, ProtectionSettingsInitialized: true}); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st, Wrapper: w, Now: func() time.Time { return time.Unix(1000, 0) }}
	s.CaptchaVerifier = NewCaptchaVerifier(st, w, transport)
	c, err := s.Challenge(context.Background(), "t", "login", "txn", "login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}
func TestCaptchaProviders(t *testing.T) {
	for _, provider := range []string{"recaptcha_v2", "hcaptcha", "friendly_captcha", "recaptcha_enterprise"} {
		t.Run(provider, func(t *testing.T) {
			for _, tc := range []struct {
				name, body string
				status     int
				want       error
			}{
				{"success", `{"success":true,"hostname":"login.example.test"}`, 200, nil},
				{"false", `{"success":false}`, 200, ErrCaptchaInvalid},
				{"wrong host", `{"success":true,"hostname":"evil.test"}`, 200, ErrCaptchaInvalid},
				{"malformed", `{`, 200, ErrCaptchaUnavailable},
				{"oversize", strings.Repeat("x", 256*1024+1), 200, ErrCaptchaUnavailable},
				{"redirect", ``, 302, ErrCaptchaUnavailable},
			} {
				t.Run(tc.name, func(t *testing.T) {
					body := tc.body
					if provider == "recaptcha_enterprise" {
						if tc.name == "success" {
							body = `{"tokenProperties":{"valid":true,"hostname":"login.example.test","action":"login"},"event":{"siteKey":"site"}}`
						} else if tc.name == "wrong host" {
							body = `{"tokenProperties":{"valid":true,"hostname":"evil.test","action":"login"},"event":{"siteKey":"site"}}`
						}
					}
					if provider == "recaptcha_enterprise" {
						body = strings.ReplaceAll(body, `"action":"login"`, `"action":"`+enterpriseAction("t", "login", "txn")+`"`)
					}
					calls := 0
					s, c := captchaFixture(t, provider, breachTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						if calls > 1 {
							t.Fatal("provider redirect followed")
						}
						if r.URL.Scheme != "https" || r.Method != "POST" {
							t.Fatalf("unsafe request %s %s", r.Method, r.URL)
						}
						if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 2*time.Second {
							t.Fatal("missing deadline")
						}
						if provider == "recaptcha_enterprise" {
							if r.URL.Host != "recaptchaenterprise.googleapis.com" || r.URL.Query().Get("key") != "secret" {
								t.Fatal("wrong enterprise authentication")
							}
						} else {
							if err := r.ParseForm(); err != nil {
								t.Fatal(err)
							}
							if r.Form.Get("secret") != "secret" {
								t.Fatal("missing secret")
							}
							if provider == "hcaptcha" || provider == "friendly_captcha" {
								if r.Form.Get("sitekey") != "site" {
									t.Fatal("missing site binding")
								}
							}
						}
						return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Location": []string{"https://evil.test"}}}, nil
					}))
					err := s.VerifyChallenge(context.Background(), c, "response")
					if !errors.Is(err, tc.want) {
						t.Fatalf("got %v want %v", err, tc.want)
					}
				})
			}
		})
	}
}
func TestCaptchaReplayAcrossInstances(t *testing.T) {
	s, c := captchaFixture(t, "recaptcha_v2", breachTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"hostname":"login.example.test"}`))}, nil
	}))
	other := *s
	if err := s.VerifyChallenge(context.Background(), c, "proof"); err != nil {
		t.Fatal(err)
	}
	c.Flow = "signup"
	c.Action = "signup"
	c.TransactionID = "other"
	if err := other.VerifyChallenge(context.Background(), c, "proof"); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatalf("replay accepted: %v", err)
	}
}
func TestCaptchaBindingFailures(t *testing.T) {
	for _, body := range []string{`{"tokenProperties":{"valid":true,"hostname":"login.example.test","action":"signup"},"event":{"siteKey":"site"}}`, `{"tokenProperties":{"valid":true,"hostname":"login.example.test","action":"login"}}`, `{"tokenProperties":{"valid":true,"action":"login"},"event":{"siteKey":"site"}}`} {
		body = strings.ReplaceAll(body, `"action":"login"`, `"action":"`+enterpriseAction("t", "login", "txn")+`"`)
		s, c := captchaFixture(t, "recaptcha_enterprise", breachTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		if err := s.VerifyChallenge(context.Background(), c, "proof"); !errors.Is(err, ErrCaptchaInvalid) {
			t.Fatal(err)
		}
	}
	for _, provider := range []string{"recaptcha_v2", "hcaptcha"} {
		s, c := captchaFixture(t, provider, breachTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}, nil
		}))
		if err := s.VerifyChallenge(context.Background(), c, "proof"); !errors.Is(err, ErrCaptchaInvalid) {
			t.Fatal(provider, err)
		}
	}
}
func TestCaptchaTimeoutAndCredentials(t *testing.T) {
	s, c := captchaFixture(t, "recaptcha_v2", breachTransport(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, errors.New("secret provider transport detail")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := s.VerifyChallenge(ctx, c, "proof"); !errors.Is(err, ErrCaptchaUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	s.Wrapper = nil
	s.CaptchaVerifier = nil
	if err := s.VerifyChallenge(context.Background(), c, "proof"); !errors.Is(err, ErrCaptchaUnavailable) {
		t.Fatal("missing wrapper", err)
	}
}
func TestCaptchaConcurrentGlobalReplay(t *testing.T) {
	s, c := captchaFixture(t, "recaptcha_v2", breachTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"hostname":"login.example.test"}`))}, nil
	}))
	ch := make(chan error, 2)
	for range 2 {
		other := *s
		go func() { ch <- other.VerifyChallenge(context.Background(), c, "shared") }()
	}
	success := 0
	for range 2 {
		err := <-ch
		if err == nil {
			success++
		} else if !errors.Is(err, ErrCaptchaInvalid) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	// Sealing the same provider secret to another tenant still cannot replay it.
	other, err := s.Store.Tenants().Get(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	other.ID = "t2"
	other.Name = "t2"
	other.ProtectionSettings, err = keys.PatchCAPTCHA(s.Wrapper, "t2", protectionrules.Defaults(), map[string]any{"active_provider_id": "recaptcha_v2", "recaptcha_v2": map[string]any{"site_key": "site", "secret": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Tenants().Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	c.TenantID = "t2"
	if err := s.VerifyChallenge(context.Background(), c, "shared"); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatal("cross tenant replay", err)
	}
}
func TestCaptchaEnterpriseTransactionAction(t *testing.T) {
	s, _ := captchaFixture(t, "recaptcha_enterprise", nil)
	a, err := s.Challenge(context.Background(), "t", "login", "one", "login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Challenge(context.Background(), "t", "login", "two", "login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if a.Action == b.Action {
		t.Fatal("enterprise action does not bind local transaction")
	}
}
