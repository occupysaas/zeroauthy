package email

import (
	"errors"
	"testing"

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
