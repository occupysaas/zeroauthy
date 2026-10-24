package protection

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type breachTransport func(*http.Request) (*http.Response, error)

func (f breachTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func digest(p string) string                                                { return fmt.Sprintf("%X", sha1.Sum([]byte(p))) }
func TestBreachRange(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		hit, bad   bool
	}{
		{"positive", digest("päss🔑")[5:] + ":2\r\n", 200, true, false},
		{"negative", strings.Repeat("A", 35) + ":1\n", 200, false, false},
		{"padding", digest("päss🔑")[5:] + ":0\n", 200, false, false},
		{"malformed", "secret garbage", 200, false, true},
		{"bad hex", strings.Repeat("Z", 35) + ":1\n", 200, false, true},
		{"negative count", digest("päss🔑")[5:] + ":-1\n", 200, false, true},
		{"count overflow", digest("päss🔑")[5:] + ":999999999999999999999\n", 200, false, true},
		{"duplicate", digest("päss🔑")[5:] + ":0\n" + digest("päss🔑")[5:] + ":1\n", 200, false, true},
		{"empty", "", 200, false, true},
		{"oversized", strings.Repeat("A", 2*1024*1024+1), 200, false, true},
		{"redirect", "", 302, false, true},
		{"status", "", 500, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := NewRangeChecker(breachTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.pwnedpasswords.com/range/"+digest("päss🔑")[:5] || r.Header.Get("Add-Padding") != "true" {
					t.Fatal("unsafe request", r.URL, r.Header)
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://evil.test"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			hit, err := c.Check(context.Background(), "päss🔑")
			if hit != tc.hit || (err != nil) != tc.bad {
				t.Fatalf("hit %v err %v", hit, err)
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}
func TestBreachCache(t *testing.T) {
	calls := 0
	now := time.Unix(1000, 0)
	c := NewRangeChecker(breachTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("A", 35) + ":1\n"))}, nil
	}))
	c.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		_, err := c.Check(context.Background(), "pw")
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	now = now.Add(5 * time.Minute)
	c.Check(context.Background(), "pw")
	if calls != 2 {
		t.Fatal(calls)
	}
	for i := 0; i < 1100; i++ {
		c.Check(context.Background(), fmt.Sprint(i))
	}
	if len(c.cache) > 1024 {
		t.Fatal(len(c.cache))
	}
}
func TestBreachTimeout(t *testing.T) {
	c := NewRangeChecker(breachTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("missing bound")
		}
		return nil, context.DeadlineExceeded
	}))
	_, err := c.Check(context.Background(), "secret")
	if !errors.Is(err, ErrBreachUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}
func TestBreachUnavailable(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "t", Name: "t", ProtectionSettings: protectionrules.Defaults(), ProtectionSettingsInitialized: true}
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st}
	if err := s.CheckPassword(ctx, tn, "login", "secret"); !errors.Is(err, ErrBreachUnavailable) {
		t.Fatal(err)
	}
	tn.ProtectionSettings.BreachedPassword.Shields = nil
	st.Tenants().Update(ctx, tn)
	if err := s.CheckPassword(ctx, tn, "login", "secret"); err != nil {
		t.Fatal(err)
	}
}

type policyChecker struct {
	hit   bool
	err   error
	calls int
}

func (c *policyChecker) Check(context.Context, string) (bool, error) { c.calls++; return c.hit, c.err }
func TestBreachStagesAndRedaction(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "t", Name: "t", ProtectionSettings: protectionrules.Defaults(), ProtectionSettingsInitialized: true}
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	p := &tn.ProtectionSettings.BreachedPassword
	p.Shields = []string{"block"}
	p.Stage.PreUserRegistration.Shields = []string{"admin_notification"}
	p.Stage.PreChangePassword.Shields = []string{"block"}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	c := &policyChecker{hit: true}
	s := &Service{Store: st, BreachChecker: c, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	for _, stage := range []string{"login", "pre-user-registration", "pre-change-password"} {
		err := s.CheckPassword(ctx, tn, stage, "secret")
		if stage == "pre-user-registration" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrPasswordLeaked) {
			t.Fatal(stage, err)
		}
	}
	c.err = fmt.Errorf("malicious provider error secret %s", digest("secret"))
	p.Shields = nil
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPassword(ctx, tn, "login", "secret"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "outcome=unavailable") || strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), digest("secret")) {
		t.Fatal("unsafe or missing event", logs.String())
	}
	p.Enabled = false
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	calls := c.calls
	if err := s.CheckPassword(ctx, tn, "login", "secret"); err != nil || c.calls != calls {
		t.Fatal("disabled called checker", err, c.calls)
	}
}
func TestBreachOffNoTransport(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "t", Name: "t", ProtectionSettings: protectionrules.Defaults(), ProtectionSettingsInitialized: true}
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st}
	if err := s.CheckPassword(ctx, tn, "login", "secret"); !errors.Is(err, ErrBreachUnavailable) {
		t.Fatal(err)
	}
}
func TestBreachConcurrentRange(t *testing.T) {
	c := NewRangeChecker(breachTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("A", 35) + ":1\n"))}, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Check(context.Background(), "parallel"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestBreachCachePrefixAndUnavailable(t *testing.T) {
	// These different passwords share only the five-character prefix B2029.
	if digest("406")[:5] != digest("678")[:5] {
		t.Fatal("fixture prefix")
	}
	calls := 0
	now := time.Unix(1, 0)
	c := NewRangeChecker(breachTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := digest("406")[5:] + ":1\n"
		if calls > 1 {
			body = "malformed"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	}))
	c.now = func() time.Time { return now }
	if hit, err := c.Check(context.Background(), "406"); !hit || err != nil {
		t.Fatal(hit, err)
	}
	if hit, err := c.Check(context.Background(), "678"); hit || err != nil || calls != 1 {
		t.Fatal("cache must be per-prefix", hit, err, calls)
	}
	now = now.Add(5 * time.Minute)
	for i := 0; i < 2; i++ {
		if _, err := c.Check(context.Background(), "406"); !errors.Is(err, ErrBreachUnavailable) {
			t.Fatal("expired clean verdict", err)
		}
	}
	if calls != 3 {
		t.Fatal("unavailable response cached", calls)
	}
}
