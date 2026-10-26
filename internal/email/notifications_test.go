package email

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestWelcomeClaimAndEligibility(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "auth0|welcome", Email: "welcome@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Welcome(ctx, "tenant-a", user.UserID, "", "en"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 0 {
		t.Fatal("absent welcome template sent")
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "welcome_email", Fields: map[string]any{"body": "<p>Welcome {{ user.email | escape }}</p>", "subject": "Welcome", "enabled": true, "syntax": "liquid"}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Welcome(ctx, "tenant-a", user.UserID, "", "en"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Welcome(ctx, "tenant-a", user.UserID, "", "en"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 || fallback.messages[0].To != user.Email {
		t.Fatalf("welcome sends=%+v", fallback.messages)
	}
	if err := svc.Welcome(ctx, "other-tenant", user.UserID, "", "en"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong tenant=%v", err)
	}
}

func TestNotificationAliasRecipient(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "auth0|canonical", Email: "primary@example.test", EmailVerified: true,
		Identities: []store.Identity{{Connection: "db", Provider: store.StrategyDatabase, UserID: "canonical", ProfileData: map[string]any{"email": "alias@example.test", "username": "alias"}}}}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blocked_account", "stolen_credentials"} {
		if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: name, Fields: map[string]any{"body": "Security notice", "subject": "Security notice", "enabled": true}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Notify(ctx, "tenant-a", user.UserID, "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Notify(ctx, "tenant-a", user.UserID, "stolen_credentials"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 || fallback.messages[0].To != user.Email || fallback.messages[0].To == "alias@example.test" || fallback.messages[1].To != user.Email {
		t.Fatalf("notification recipient=%+v", fallback.messages)
	}
	if err := svc.Notify(ctx, "tenant-a", "alias@example.test", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 {
		t.Fatal("alias identifier caused a notification")
	}
}

func TestNotificationConcurrentInstances(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "u", Email: "u@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "blocked_account", Fields: map[string]any{"body": "Security notice", "subject": "Security notice", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	other := *svc
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := other.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	fallback.mu.Lock()
	count := len(fallback.messages)
	fallback.mu.Unlock()
	if count != 1 {
		t.Fatalf("concurrent sends=%d", count)
	}
}

func TestNotificationFailedSendClaim(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "u", Email: "u@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "blocked_account", Fields: map[string]any{"body": "Security notice", "subject": "Security notice", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	fallback.err = errors.New("uncertain transport")
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err == nil {
		t.Fatal("send failure hidden")
	}
	fallback.err = nil
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 {
		t.Fatalf("uncertain send retried: %d", len(fallback.messages))
	}
}

func TestNotificationClaimPurgedAfterUserDeletion(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "u", Email: "u@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "blocked_account", Fields: map[string]any{"body": "Security notice", "subject": "Security notice", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Delete(ctx, "tenant-a", "u"); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 {
		t.Fatalf("user deletion retained claim: sends=%d", len(fallback.messages))
	}
}

func TestNotificationClaimsPurgedAfterTenantDeletion(t *testing.T) {
	ctx, st, _, _, _, _ := emailServiceFixture(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	if ok, err := st.EmailNotifications().Claim(ctx, "tenant-a", "u", "blocked_account", "day", now, now.Add(12*time.Hour), 1); err != nil || !ok {
		t.Fatalf("initial claim=%v,%v", ok, err)
	}
	if err := st.Tenants().Delete(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant-a", Name: "tenant-a"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.EmailNotifications().Claim(ctx, "tenant-a", "u", "blocked_account", "day", now, now.Add(12*time.Hour), 1); err != nil || !ok {
		t.Fatalf("tenant deletion retained claim=%v,%v", ok, err)
	}
}

func TestNotificationFixedUTCWindow(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	user := &store.User{TenantID: "tenant-a", UserID: "u", Email: "u@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "blocked_account", Fields: map[string]any{"body": "Security notice", "subject": "Security notice", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 23, 59, 59, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := svc.Notify(ctx, "tenant-a", "u", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 {
		t.Fatalf("UTC-day notifications=%d", len(fallback.messages))
	}
}

func TestSecurityNotificationMessageCopy(t *testing.T) {
	l := i18n.New(&store.Tenant{Name: "zeroauthy", FriendlyName: "zeroauthy"}, "en")
	blocked := SecurityNotificationMessage(l, "blocked_account", "u@example.test")
	stolen := SecurityNotificationMessage(l, "stolen_credentials", "u@example.test")
	if blocked.To != "u@example.test" || !strings.Contains(blocked.Subject, "blocked") || !strings.Contains(blocked.Text, "repeated failures") {
		t.Fatalf("blocked message=%+v", blocked)
	}
	if stolen.To != "u@example.test" || !strings.Contains(stolen.Subject, "password") || !strings.Contains(stolen.Text, "data breach") {
		t.Fatalf("stolen message=%+v", stolen)
	}
}

func TestCanonicalSecurityNotificationText(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	u := &store.User{TenantID: "tenant-a", UserID: "u-canonical", Email: "canonical@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tenant, err := st.Tenants().Get(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	tenant.CustomText = store.CustomText{"zeroauthy": {"en": {"email-blocked-account": {"subject": "Legacy subject"}}}}
	if err := st.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	c := &store.HostedLoginConfig{TenantID: "tenant-a", CustomText: store.CustomText{"zeroauthy": {"en": {"email-blocked-account": {"subject": "Canonical subject"}}}}}
	if err := st.HostedLogins().Put(ctx, c, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Notify(ctx, "tenant-a", u.UserID, "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 || fallback.messages[0].Subject != "Canonical subject" {
		t.Fatalf("notification=%+v", fallback.messages)
	}
}

func TestWelcomeFailedSendKeepsPermanentClaim(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	fallback.err = errors.New("transport failed")
	user := &store.User{TenantID: "tenant-a", UserID: "auth0|welcome", Email: "welcome@example.test", EmailVerified: true}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "welcome_email", Fields: map[string]any{"body": "Welcome", "subject": "Welcome", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Welcome(ctx, "tenant-a", user.UserID, "", "en"); err == nil {
		t.Fatal("send failure hidden")
	}
	fallback.err = nil
	if err := svc.Welcome(ctx, "tenant-a", user.UserID, "", "en"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 {
		t.Fatalf("failed welcome retried: %d", len(fallback.messages))
	}
}

func TestEmailRedirectRequiresExactTrustedHTTPSDestination(t *testing.T) {
	ctx, st, _, _, _, _ := emailServiceFixture(t)
	tn, _ := st.Tenants().Get(ctx, "tenant-a")
	tn.Domains = []string{"tenant-a.example.test"}
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "tenant-a", ClientID: "client-a", Callbacks: []string{"https://app.example.test/callback?done=1"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		client, url string
		valid       bool
	}{
		{"client-a", "https://app.example.test/callback?done=1", true},
		{"client-a", "https://app.example.test/callback?done=2", false},
		{"client-a", "https://app.example.test/callback-evil", false},
		{"missing", "https://app.example.test/callback?done=1", false},
		{"client-a", "http://app.example.test/callback?done=1", false},
		{"client-a", "https://user@app.example.test/callback?done=1", false},
		{"client-a", "https://app.example.test/callback?done=1#fragment", false},
		{"", "https://tenant-a.example.test/complete", true},
		{"", "https://outside.example.test/complete", false},
		{"client-a", "{{ url }}", false},
	} {
		err := ValidateEmailRedirect(ctx, st, "tenant-a", tc.client, tc.url)
		if tc.valid && err != nil {
			t.Errorf("valid %q: %v", tc.url, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("unsafe destination accepted: %q", tc.url)
		}
	}
}
