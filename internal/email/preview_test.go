package email

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPreviewUsesSyntheticContextAndOverrides(t *testing.T) {
	ctx, st, _, _, _, svc := emailServiceFixture(t)
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "verify_email", Fields: map[string]any{"body": "<p>{{ user.email | escape }} {{ url }}</p>", "subject": "Verify {{ tenant.name }}", "enabled": true, "resultUrl": "https://real.example.test/callback"}}, 0); err != nil {
		t.Fatal(err)
	}
	out, err := svc.Preview(ctx, "tenant-a", "verify_email", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.HTML, "preview@example.invalid") || !strings.Contains(out.HTML, "https://example.invalid/verify_email") || out.ResultURL != "https://example.invalid/verify_email" || strings.Contains(out.HTML, "real.example.test") {
		t.Fatalf("preview=%+v", out)
	}
	out, err = svc.Preview(ctx, "tenant-a", "verify_email", map[string]any{"subject": "Unsaved {{ tenant.name }}", "body": "{{ user.email }}"})
	if err != nil || out.Subject != "Unsaved tenant-a" || out.HTML != "preview@example.invalid" {
		t.Fatalf("override=%+v, %v", out, err)
	}
	if _, err = svc.Preview(ctx, "tenant-a", "verify_email", map[string]any{"resultUrl": "https://attacker.example/"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unsafe override=%v", err)
	}
}

func TestSendTestRendersForVerifiedOperatorAddress(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "verify_email", Fields: map[string]any{"body": "Hello {{ user.email }}", "subject": "Test", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendTest(ctx, "tenant-a", "verify_email", "operator@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 || fallback.messages[0].To != "operator@example.test" || fallback.messages[0].Text != "Hello operator@example.test" {
		t.Fatalf("test message=%+v", fallback.messages)
	}
}
