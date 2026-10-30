package sqlstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestInvitationAcceptanceSQL(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			st := mk(t)
			ctx := context.Background()
			now := time.Now().UTC()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			must(st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}))
			must(st.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "client", IsFirstParty: true, OrganizationUsage: store.OrgUsageAllow}))
			must(st.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "conn", Name: "db", Strategy: "auth0", EnabledClients: []string{"client"}}))
			must(st.Organizations().Create(ctx, &store.Organization{TenantID: "t", ID: "org_0000000000000001", Name: "org", DisplayName: "org"}, []store.OrganizationConnection{{ConnectionID: "conn", ShowAsButton: true}}))
			must(st.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u", Email: "person@example.test", EmailVerified: true}))
			must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "session", TokenHash: "hash", UserID: "auth0|u", Connection: "db", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)}))
			must(st.OrganizationsII().CreateInvitation(ctx, &store.OrganizationInvitation{TenantID: "t", OrganizationID: "org_0000000000000001", ID: "invite", ClientID: "client", InviteeEmail: "person@example.test", TicketHash: "ticket-hash", WrappedTicket: []byte("wrapped"), ExpiresAt: now.Add(time.Hour)}))
			must(st.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "txn", ClientID: "client", ExpiresAt: now.Add(time.Hour), Params: map[string]string{store.TxnParamOrgID: "org_0000000000000001", store.TxnParamOrgMode: "fixed", orglogin.InvitationIDParam: "invite", orglogin.InvitationClientParam: "client", orglogin.InvitationSessionParam: "session"}}))
			in := orglogin.AcceptanceInput{TenantID: "t", OrganizationID: "org_0000000000000001", ClientID: "client", InvitationID: "invite", TransactionID: "txn", UserID: "auth0|u", PrimaryConnectionID: "conn", Now: now}
			_, err := orglogin.AcceptInvitation(ctx, st, in)
			must(err)
			_, err = orglogin.AcceptInvitation(ctx, st, in)
			must(err)
			member, err := st.Organizations().IsMember(ctx, "t", in.OrganizationID, in.UserID)
			must(err)
			if !member {
				t.Fatal("missing member")
			}
		})
	}
}
