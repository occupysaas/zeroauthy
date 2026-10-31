package login

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The post-login picker resolves client/connection before inserting membership.
func TestOrganizationPickerMembershipEventAttribution(t *testing.T) {
	e := newEnv(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, true, false)
	ctx := context.Background()
	client, err := e.st.Clients().Get(ctx, org.TenantID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	client.Name = "Picker app"
	if err := e.st.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	sess := &store.LoginSession{TenantID: org.TenantID, ID: "picker-session", UserID: user.UserID, Connection: conn.Name, ExpiresAt: fixedNow().Add(time.Hour)}
	if err := e.st.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	txn := &store.AuthTransaction{TenantID: org.TenantID, ID: "picker-txn", ClientID: "spa", ExpiresAt: fixedNow().Add(time.Hour), Params: map[string]string{store.TxnParamOrgMode: string(authz.OrgPickAfter), "za_org_session": sess.ID}}
	if err := e.st.AuthTransactions().Create(ctx, txn); err != nil {
		t.Fatal(err)
	}
	capture := &eventRecorder{}
	ctx = logs.WithRecorder(ctx, capture)
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil).WithContext(ctx)
	f := &flow{res: tenant.Resolved{Tenant: mustTenant(t, e, "acme")}, txn: txn}
	if err := e.h.bindOrg(r, f, org); err != nil {
		t.Fatal(err)
	}
	member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
	if err != nil || !member || f.txn.Params[store.TxnParamOrgID] != org.ID || f.txn.Params[store.TxnParamOrgMode] != string(authz.OrgFixed) {
		t.Fatalf("binding=%+v membership=%v err=%v", f.txn, member, err)
	}
	if len(capture.events) != 1 {
		t.Fatalf("events=%+v", capture.events)
	}
	got := capture.events[0]
	if got.Type != "organization_member_added" || got.TenantID != org.TenantID || got.ClientID != "spa" || got.ClientName != "Picker app" || got.UserID != user.UserID || got.ConnectionID != conn.ID || got.Connection != "Username-Password-Authentication" || got.Strategy != "auth0" || got.StrategyType != "database" || got.OrganizationID != org.ID || got.OrganizationName != "acme-org" {
		t.Fatalf("event=%+v", got)
	}
}
