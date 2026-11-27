package email

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The CIBA approval email: the built-in body, then the tenant's enabled
// async_approval template with application.name, url and binding_message.
func TestSendAsyncApproval(t *testing.T) {
	ctx, st, _, fallback, _, svc := emailServiceFixture(t)
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "tenant-a", ClientID: "agent", Name: "Agent <Backend>"}); err != nil {
		t.Fatal(err)
	}
	user := &store.User{UserID: "auth0|ada", Email: "ada@example.test"}
	link := "https://acme.test/bc-verify?consent=single-use-value"
	m := AsyncApprovalEmail{TenantID: "tenant-a", ClientID: "agent", User: user, URL: link, BindingMessage: "ORDER-42"}
	if err := svc.SendAsyncApproval(ctx, m); err != nil {
		t.Fatal(err)
	}
	got := fallback.messages[len(fallback.messages)-1]
	if got.Type != AsyncApprovalTemplate || got.To != "ada@example.test" || !strings.Contains(got.HTML, "ORDER-42") || !strings.Contains(got.HTML, "consent=single-use-value") ||
		!strings.Contains(got.HTML, "Agent &lt;Backend&gt;") || got.Subject != defaultAsyncApprovalSubject {
		t.Fatalf("built-in message = %+v", got)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: AsyncApprovalTemplate, Fields: map[string]any{
		"template": AsyncApprovalTemplate, "body": "{{application.name}} says click on {{url}}, binding message: {{binding_message}}", "subject": "Action Required", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendAsyncApproval(ctx, m); err != nil {
		t.Fatal(err)
	}
	got = fallback.messages[len(fallback.messages)-1]
	if got.Subject != "Action Required" || !strings.Contains(got.HTML, "binding message: ORDER-42") || !strings.Contains(got.HTML, "consent=single-use-value") {
		t.Fatalf("template message = %+v", got)
	}
}
