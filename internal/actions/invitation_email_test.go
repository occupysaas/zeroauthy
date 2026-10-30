package actions_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func invitationActionFixture(t *testing.T, code string) (*harness, *store.Action, orglogin.InvitationTicket) {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	org := &store.Organization{TenantID: "t1", ID: "org_1234567890123456", Name: "team"}
	if err := h.st.Organizations().Create(ctx, org, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Clients().Create(ctx, &store.Client{TenantID: "t1", ClientID: "c", Name: "Original"}); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: "t1", OrganizationID: org.ID, ID: "uinv_a", ClientID: "c", InviteeEmail: "invited@example.test", ExpiresAt: h.clock().Add(30 * 24 * time.Hour)}
	ticket, err := orglogin.IssueInvitationTicket(h.w, inv, "https://app.example/login", "team")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	a := h.action("t1", actions.TriggerCustomEmailProvider, "invite-mail", code, nil, false)
	h.bind("t1", a.Trigger, a)
	if err = h.st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "t1", Name: "custom", Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
	renderer, _ := email.NewRenderer()
	h.eng.InvitationEmail = &email.Service{Store: h.st, Wrapper: h.w, Renderer: renderer, DefaultFrom: "sender@example.test"}
	if err = h.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "t1", Name: "user_invitation", Fields: map[string]any{"body": "<p>{{ inviter.name | escape }} {{ application.name }} {{ organization.display_name }} {{ url }}</p>", "subject": "Frozen subject"}}, 0); err != nil {
		t.Fatal(err)
	}
	if err = h.st.WithTx(ctx, func(tx store.Store) error {
		return h.eng.EnqueueInvitation(ctx, tx, actions.InvitationDelivery{TenantID: "t1", OrganizationID: org.ID, InvitationID: inv.ID, ClientID: "c", InviterName: "Inviter", OrganizationDisplayName: "Frozen Team", ApplicationName: "Frozen App", NotificationHost: "login.example.test", TenantFriendlyName: "Frozen Tenant", Language: "de"})
	}); err != nil {
		t.Fatal(err)
	}
	return h, a, ticket
}
func TestInvitationEmailPendingActionFrozenContext(t *testing.T) {
	h, a, _ := invitationActionFixture(t, `exports.onExecuteCustomEmailProvider=(e,a)=>{if(e.client.name!=='Frozen App'||e.tenant.friendly_name!=='Frozen Tenant'||e.request.hostname!=='login.example.test'||e.notification.subject!=='Frozen subject'||!e.notification.html.includes('Inviter Frozen App Frozen Team')||e.notification.locale!=='de'||e.notification.message_type!=='user_invitation')throw Error('changed context');a.notification.retry('temporary')}`)
	h.redeploy(a, `exports.onExecuteCustomEmailProvider=()=>{throw Error('replacement ran')}`)
	h.bind("t1", a.Trigger)
	ctx := context.Background()
	tmpl, err := h.st.EmailTemplates().Get(ctx, "t1", "user_invitation")
	if err != nil {
		t.Fatal(err)
	}
	tmpl.Fields["subject"] = "Changed"
	if err = h.st.EmailTemplates().Put(ctx, tmpl, tmpl.Revision); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		j := claimJob(t, h)
		n := finishJob(t, h, &j)
		want := "pending"
		if i == 5 {
			want = "failed"
		}
		if n.Status != want {
			t.Fatalf("attempt %d: %s logs %s", i+1, n.Status, h.logs.String())
		}
		ex, err := h.st.Actions().GetExecution(ctx, "t1", n.ExecutionIDs[len(n.ExecutionIDs)-1])
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range ex.Results {
			if r.ErrorID != "" {
				t.Fatalf("pinned event failed: %s", r.ErrorMsg)
			}
		}
		h.advance(n.NextAt.Sub(h.clock()))
	}
}
func TestInvitationEmailActionTicketDiagnosticsRedacted(t *testing.T) {
	h, _, ticket := invitationActionFixture(t, `exports.onExecuteCustomEmailProvider=(e,a)=>{const u=e.notification.html.match(/https:[^< ]+/)[0];throw Error(u)}`)
	j := claimJob(t, h)
	n := finishJob(t, h, &j)
	if n.Status != "pending" {
		t.Fatalf("status %s logs %s", n.Status, h.logs.String())
	}
	ex, err := h.st.Actions().GetExecution(context.Background(), "t1", n.ExecutionIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ex)
	if strings.Contains(string(raw), ticket.TicketID) || strings.Contains(h.logs.String(), ticket.TicketID) {
		t.Fatal("ticket leaked into diagnostics")
	}
}
