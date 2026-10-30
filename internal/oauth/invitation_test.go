package oauth

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
	"time"
)

func TestInvitationPARBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	c, err := f.st.Clients().Get(ctx, tid, "par-web")
	if err != nil {
		t.Fatal(err)
	}
	c.OrganizationUsage = store.OrgUsageAllow
	if err = f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	o := &store.Organization{TenantID: tid, ID: "org_0000000000000001", Name: "invite-org", DisplayName: "invite-org"}
	if err = f.st.Organizations().Create(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: tid, OrganizationID: o.ID, ID: "invite", ClientID: c.ClientID, InviteeEmail: "alice@acme.test", TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err = f.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	rec, body := f.par(t, "acme.example.test", formType, parForm("organization", o.ID, "invitation", "bearer", orglogin.InvitationIDParam, "evil", orglogin.InvitationSessionParam, "evil").Encode())
	if rec.Code != 201 {
		t.Fatal(rec.Code, body)
	}
	id := strings.TrimPrefix(body["request_uri"].(string), authz.RequestURIPrefix)
	p, err := f.st.PushedAuthRequests().Get(ctx, tid, secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	if p.Params["invitation"] != "" || p.Params[orglogin.InvitationIDParam] != inv.ID || p.Params[orglogin.InvitationSessionParam] != "" {
		t.Fatal(p.Params)
	}
}
