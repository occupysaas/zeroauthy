package orglogin

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"sync"
	"testing"
	"time"
)

func acceptanceFixture(t *testing.T) (*memory.Store, AcceptanceInput) {
	ctx := context.Background()
	st, o, c := entitlementFixture(t)
	now := time.Now().UTC()
	conn := &store.Connection{TenantID: "t", ID: "con_0000000000000001", Name: "db", Strategy: "auth0", EnabledClients: []string{c.ClientID}}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.Connections().Create(ctx, conn))
	must(st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: "t", OrganizationID: o.ID, ConnectionID: conn.ID, IsEnabled: true, IsEnabledSet: true, ShowAsButton: true}, true))
	u := &store.User{TenantID: "t", UserID: "auth0|u", Email: "person@example.test", EmailVerified: true, UserMetadata: map[string]any{"existing": "original"}}
	must(st.Users().Create(ctx, u))
	must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "session", UserID: u.UserID, Connection: "db", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)}))
	must(st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t", ID: "role", Name: "invited-role"}))
	invite := &store.OrganizationInvitation{TenantID: "t", OrganizationID: o.ID, ID: "invite", ClientID: c.ClientID, InviteeEmail: u.Email, Roles: []string{"role"}, TicketHash: "hash", WrappedTicket: []byte("sealed"), ExpiresAt: now.Add(time.Hour), UserMetadata: map[string]any{"existing": "replace", "new": "added"}}
	must(st.OrganizationsII().CreateInvitation(ctx, invite))
	txn := &store.AuthTransaction{TenantID: "t", ID: "txn", ClientID: c.ClientID, ExpiresAt: now.Add(time.Hour), Params: map[string]string{store.TxnParamOrgID: o.ID, store.TxnParamOrgMode: "fixed", InvitationIDParam: invite.ID, InvitationClientParam: c.ClientID, InvitationSessionParam: "session"}}
	must(st.AuthTransactions().Create(ctx, txn))
	in := AcceptanceInput{TenantID: "t", OrganizationID: o.ID, ClientID: c.ClientID, InvitationID: invite.ID, TransactionID: txn.ID, UserID: u.UserID, PrimaryConnectionID: conn.ID, Now: now}
	return st, in
}
func TestInvitationAcceptance(t *testing.T) {
	st, in := acceptanceFixture(t)
	ctx := context.Background()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	receipt, err := AcceptInvitation(ctx, st, in)
	must(err)
	if receipt.UserID != in.UserID {
		t.Fatal(receipt)
	}
	member, err := st.Organizations().IsMember(ctx, "t", in.OrganizationID, in.UserID)
	must(err)
	if !member {
		t.Fatal("missing member")
	}
	got, err := st.Users().Get(ctx, "t", in.UserID)
	must(err)
	if got.UserMetadata["existing"] != "original" || got.UserMetadata["new"] != "added" {
		t.Fatal(got.UserMetadata)
	}
	roles, err := st.Organizations().MemberRoles(ctx, "t", in.OrganizationID, in.UserID, store.OrgPage{PerPage: 100})
	must(err)
	if len(roles.Items) != 1 || roles.Items[0] != "role" {
		t.Fatal(roles)
	}
	tenantRoles, err := st.RBAC().UserRoles(ctx, "t", in.UserID, store.RBACPage{PerPage: 100})
	must(err)
	if len(tenantRoles.Items) != 0 {
		t.Fatal(tenantRoles)
	}
	_, err = AcceptInvitation(ctx, st, in)
	must(err)
	in.UserID = "other"
	if _, err = AcceptInvitation(ctx, st, in); err == nil {
		t.Fatal("receipt accepted for another user")
	}
}

func TestInvitationAcceptanceFailures(t *testing.T) {
	for _, name := range []string{"wrong email", "unverified", "blocked", "expired", "connection disabled", "client policy", "entitlement", "deleted role", "different transaction", "session spoof", "forced linked connection", "disabled signup"} {
		t.Run(name, func(t *testing.T) {
			st, in := acceptanceFixture(t)
			ctx := context.Background()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			u, e := st.Users().Get(ctx, in.TenantID, in.UserID)
			must(e)
			switch name {
			case "disabled signup":
				txn, e := st.AuthTransactions().Get(ctx, "t", "txn")
				must(e)
				txn.Params[InvitationSignupParam] = "1"
				must(st.AuthTransactions().Delete(ctx, "t", "txn"))
				must(st.AuthTransactions().Create(ctx, txn))
			case "wrong email":
				u.Email = "other@example.test"
				must(st.Users().Update(ctx, u))
			case "unverified":
				u.EmailVerified = false
				must(st.Users().Update(ctx, u))
			case "blocked":
				u.Blocked = true
				must(st.Users().Update(ctx, u))
			case "expired":
				in.Now = in.Now.Add(time.Hour)
			case "connection disabled":
				link, e := st.Organizations().GetConnection(ctx, in.TenantID, in.OrganizationID, in.PrimaryConnectionID)
				must(e)
				link.IsEnabled = false
				link.IsEnabledSet = true
				must(st.Organizations().PutConnection(ctx, *link, false))
			case "client policy":
				c, e := st.Clients().Get(ctx, in.TenantID, in.ClientID)
				must(e)
				c.OrganizationUsage = store.OrgUsageDeny
				must(st.Clients().Update(ctx, c))
			case "entitlement":
				o, e := st.Organizations().Get(ctx, in.TenantID, in.OrganizationID)
				must(e)
				o.IsAppEntitlementActive = true
				must(st.Organizations().Update(ctx, o))
			case "deleted role":
				must(st.RBAC().DeleteRole(ctx, in.TenantID, "role"))
			case "different transaction":
				in.TransactionID = "other"
			case "session spoof":
				in.UserID = "other"
			case "forced linked connection":
				in.PrimaryConnectionID = "another-linked-connection"
			}
			if _, err := AcceptInvitation(ctx, st, in); err == nil {
				t.Fatal("accepted invalid invitation")
			}
			if _, err := st.OrganizationsII().GetInvitationReceipt(ctx, "t", "txn"); err == nil {
				t.Fatal("failure created receipt")
			}
			member, err := st.Organizations().IsMember(ctx, "t", in.OrganizationID, "auth0|u")
			must(err)
			if member {
				t.Fatal("failure enrolled user")
			}
		})
	}
}
func TestInvitationAcceptanceConcurrent(t *testing.T) {
	st, in := acceptanceFixture(t)
	ctx := context.Background()
	txn, e := st.AuthTransactions().Get(ctx, "t", "txn")
	if e != nil {
		t.Fatal(e)
	}
	txn.ID = "txn2"
	if e = st.AuthTransactions().Create(ctx, txn); e != nil {
		t.Fatal(e)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"txn", "txn2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			copy := in
			copy.TransactionID = id
			_, e := AcceptInvitation(ctx, st, copy)
			results <- e
		}(id)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("success=%d", success)
	}
}
