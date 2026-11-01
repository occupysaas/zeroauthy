package orglogin_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func capturedContext(t *testing.T, st store.Store, tid, typ string) map[string]any {
	t.Helper()
	rows, err := st.Events().EventsAfter(context.Background(), tid, 0, []string{typ}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("events %s: count=%d err=%v", typ, len(rows), err)
	}
	var body map[string]any
	if err := json.Unmarshal(rows[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	return body["data"].(map[string]any)["context"].(map[string]any)
}

func TestInvitationAcceptanceEmitsMemberAdded(t *testing.T) {
	raw := memory.New()
	ctx := context.Background()
	now := time.Now().UTC()
	in := orglogin.AcceptanceInput{TenantID: "t", OrganizationID: "org_0000000000000001", ClientID: "client", InvitationID: "invite", TransactionID: "txn", UserID: "auth0|u", PrimaryConnectionID: "con_0000000000000001", Now: now}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(raw.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant", CanonicalHost: "tenant.example.test"}))
	must(raw.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "client", Name: "app", IsFirstParty: true, OrganizationUsage: store.OrgUsageAllow}))
	must(raw.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: in.PrimaryConnectionID, Name: "db", Strategy: "auth0", EnabledClients: []string{"client"}}))
	must(raw.Organizations().Create(ctx, &store.Organization{TenantID: "t", ID: in.OrganizationID, Name: "org", DisplayName: "org", ThirdPartyClientAccess: "block"}, nil))
	must(raw.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: "t", OrganizationID: in.OrganizationID, ConnectionID: in.PrimaryConnectionID, IsEnabled: true, IsEnabledSet: true, ShowAsButton: true}, true))
	must(raw.Users().Create(ctx, &store.User{TenantID: "t", UserID: in.UserID, Email: "person@example.test", EmailVerified: true}))
	must(raw.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "session", UserID: in.UserID, Connection: "db", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)}))
	must(raw.OrganizationsII().CreateInvitation(ctx, &store.OrganizationInvitation{TenantID: "t", OrganizationID: in.OrganizationID, ID: "invite", ClientID: "client", InviteeEmail: "person@example.test", TicketHash: "hash", WrappedTicket: []byte("sealed"), ExpiresAt: now.Add(time.Hour)}))
	must(raw.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "txn", ClientID: "client", ExpiresAt: now.Add(time.Hour), Params: map[string]string{store.TxnParamOrgID: in.OrganizationID, store.TxnParamOrgMode: "fixed", orglogin.InvitationIDParam: "invite", orglogin.InvitationClientParam: "client", orglogin.InvitationSessionParam: "session"}}))
	st := events.Wrap(raw, events.Config{})
	if _, err := orglogin.AcceptInvitation(context.Background(), st, in); err != nil {
		t.Fatal(err)
	}
	c := capturedContext(t, st, in.TenantID, "organization.member.added")
	if c["client"] == nil || c["connection"] == nil {
		t.Fatal(c)
	}
	if _, err := orglogin.AcceptInvitation(context.Background(), st, in); err != nil {
		t.Fatal(err)
	}
	capturedContext(t, st, in.TenantID, "organization.member.added")
}
