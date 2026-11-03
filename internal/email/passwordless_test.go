package email

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func passwordlessConnectionEmail(t *testing.T) *connrules.EmailOptions {
	t.Helper()
	opts, err := connrules.PasswordlessOf(store.Connection{Name: "email", Strategy: "email"}, nil)
	if err != nil || opts.Email == nil || opts.Email.Body == "" || opts.Email.Subject == "" {
		t.Fatalf("default email connection options = %+v %v", opts, err)
	}
	return opts.Email
}

func TestSendPasswordlessConnectionBody(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "tenant-a", ClientID: "cli", Name: "Portal"}); err != nil {
		t.Fatal(err)
	}
	def := passwordlessConnectionEmail(t)
	// The default connection body renders an 8-digit code and the app name.
	m := PasswordlessEmail{TenantID: "tenant-a", ClientID: "cli", To: "ada@example.test", Code: "12345678", From: def.From, Subject: def.Subject, Body: def.Body}
	if err := svc.SendPasswordless(ctx, m); err != nil {
		t.Fatal(err)
	}
	got := fallback.messages[len(fallback.messages)-1]
	if got.To != "ada@example.test" || !strings.Contains(got.HTML, "12345678") || !strings.Contains(got.Subject, "Portal") || got.Type != PasswordlessTemplate {
		t.Fatalf("message = %+v", got)
	}
	// A link renders through {{ link }}.
	m.Code, m.Link, m.Body = "", "https://acme.test/passwordless/verify_redirect?verification_code=tok", `<a href="{{ link }}">go</a>`
	if err := svc.SendPasswordless(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got := fallback.messages[len(fallback.messages)-1]; !strings.Contains(got.HTML, "verification_code=tok") {
		t.Fatalf("link message = %+v", got)
	}
	// No body and no template is invalid.
	if err := svc.SendPasswordless(ctx, PasswordlessEmail{TenantID: "tenant-a", To: "ada@example.test", Code: "123456"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("empty body = %v", err)
	}
}

func TestSendPasswordlessCodeTemplate(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	put := func(enabled bool, version int64) {
		t.Helper()
		if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: PasswordlessTemplate, Fields: map[string]any{
			"template": PasswordlessTemplate, "body": "<p>Template code {{ code }}</p>", "subject": "Template subject", "from": "tpl@example.test", "enabled": enabled}}, version); err != nil {
			t.Fatal(err)
		}
	}
	m := PasswordlessEmail{TenantID: "tenant-a", To: "ada@example.test", Code: "4321", From: "conn@example.test", Subject: "Connection subject", Body: "<p>Connection code {{ code }}</p>"}
	put(true, 0)
	if err := svc.SendPasswordless(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got := fallback.messages[len(fallback.messages)-1]; got.Subject != "Template subject" || got.From != "tpl@example.test" || !strings.Contains(got.HTML, "Template code 4321") {
		t.Fatalf("enabled template = %+v", got)
	}
	// Links never use the code template.
	link := m
	link.Code, link.Link, link.Body = "", "https://acme.test/l", `<p>{{ link }}</p>`
	if err := svc.SendPasswordless(ctx, link); err != nil {
		t.Fatal(err)
	}
	if got := fallback.messages[len(fallback.messages)-1]; got.Subject != "Connection subject" {
		t.Fatalf("link used template: %+v", got)
	}
	put(false, 1)
	if err := svc.SendPasswordless(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got := fallback.messages[len(fallback.messages)-1]; got.Subject != "Connection subject" || !strings.Contains(got.HTML, "Connection code 4321") {
		t.Fatalf("disabled template = %+v", got)
	}
}
