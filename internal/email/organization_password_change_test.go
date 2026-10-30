package email

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestOrganizationPasswordChangeContext(t *testing.T) {
	ctx, st, _, mail, _, svc := emailServiceFixture(t)
	org := &store.Organization{TenantID: "tenant-a", ID: "org_0000000000000014", Name: "reset-org", DisplayName: "Reset Team"}
	for _, err := range []error{st.Organizations().Create(ctx, org, nil), st.Users().Create(ctx, &store.User{TenantID: "tenant-a", UserID: "user-a", Email: "a@example.test"}), st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "reset_email", Fields: map[string]any{"template": "reset_email", "enabled": true, "body": "<p>{{ organization.id }} {{ organization.display_name }}</p>", "subject": "Reset"}}, 0)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Variables may customize presentation, but cannot replace the resolved context.
	event := Event{TenantID: "tenant-a", UserID: "user-a", Template: "reset_email", Variables: map[string]any{"organization": map[string]any{"id": "forged", "display_name": "Forged"}}}
	// Unbound presentation variables cannot impersonate an organization.
	if err := svc.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	if len(mail.messages) != 1 || strings.Contains(mail.messages[0].Text, "forged") {
		t.Fatalf("untrusted organization accepted: %+v", mail.messages)
	}
	event.OrganizationID = org.ID
	if err := svc.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	if len(mail.messages) != 2 || !strings.Contains(mail.messages[1].Text, org.ID+" "+org.DisplayName) {
		t.Fatalf("missing organization email context: %+v", mail.messages)
	}
	if err := st.Organizations().Delete(ctx, org.TenantID, org.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Send(ctx, event); err == nil {
		t.Fatal("removed organization fell back")
	}
}
