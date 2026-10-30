package authz

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func invitationEnv(t *testing.T) (*env, *store.Organization, *store.OrganizationInvitation) {
	t.Helper()
	e := newEnv(t)
	return prepareInvitationEnv(t, e)
}
func prepareInvitationEnv(t *testing.T, e *env) (*env, *store.Organization, *store.OrganizationInvitation) {
	ctx := context.Background()
	setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
	o := addOrg(t, e.st, e.tenant.ID, "", "invite-org", "")
	conn, err := e.st.Connections().GetByName(ctx, e.tenant.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: e.tenant.ID, OrganizationID: o.ID, ConnectionID: conn.ID, IsEnabled: true, IsEnabledSet: true, ShowAsButton: true}, true); err != nil {
		t.Fatal(err)
	}
	if err = e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tenant.ID, ID: "invited-role", Name: "invited-role"}); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: e.tenant.ID, OrganizationID: o.ID, ID: "invite", ClientID: "spa", InviteeEmail: "alice@acme.test", ConnectionID: conn.ID, Roles: []string{"invited-role"}, AppMetadata: map[string]any{"invited": "value"}, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err = e.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	return e, o, inv
}
func TestInvitationBoundResume(t *testing.T) {
	e, o, inv := invitationEnv(t)
	ctx := context.Background()
	q := with(goodQuery(), "organization", o.ID, "invitation", "bearer", orglogin.InvitationIDParam, "attacker", orglogin.InvitationClientParam, "attacker")
	rec := e.get(t, q)
	loc := location(t, rec)
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["invitation"] != "" || txn.Params[orglogin.InvitationIDParam] != inv.ID || txn.Params[orglogin.InvitationClientParam] != "spa" {
		t.Fatal(txn.Params)
	}
	// Browser org/client/session assertions are ignored; Resume uses stored Params.
	ck := e.login(t, fixedNow())
	sess := e.session(t, ck)
	u, err := e.st.Users().Get(ctx, e.tenant.ID, sess.UserID)
	if err != nil {
		t.Fatal(err)
	}
	u.EmailVerified = true
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login?organization=evil&client_id=evil&za_invitation_session=evil", nil)
	out := httptest.NewRecorder()
	e.h.Resume(out, r, e.res(), txn, sess)
	if location(t, out).Query().Get("code") == "" {
		t.Fatal(out.Header(), out.Body)
	}
	receipt, err := e.st.OrganizationsII().GetInvitationReceipt(ctx, e.tenant.ID, txn.ID)
	if err != nil || receipt.UserID != sess.UserID {
		t.Fatal(receipt, err)
	}
}
func TestInvitationAcceptanceFailures(t *testing.T) {
	for _, tc := range []struct{ name, key, value, code string }{
		{"silent", "prompt", "none", "interaction_required"},
		{"bad pkce", "code_challenge", "bad", "invalid_request"},
		{"bad callback", "redirect_uri", "https://evil.test/cb", "invalid_request"},
		{"wrong org", "organization", "org_0000000000000000", "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, o, inv := invitationEnv(t)
			q := with(goodQuery(), "organization", o.ID, "invitation", "bearer", tc.key, tc.value)
			req := ParseRequest(q)
			_, err, _ := ValidateRequest(context.Background(), e.st, e.tenant, &req)
			if err == nil || err.Code != tc.code {
				t.Fatal(err)
			}
			if _, err := e.st.OrganizationsII().GetInvitation(context.Background(), e.tenant.ID, o.ID, inv.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvitationBoundResumePAR(t *testing.T) {
	e, o, inv := invitationEnv(t)
	ctx := context.Background()
	req := ParseRequest(with(goodQuery(), "organization", o.ID, "invitation", "bearer"))
	if _, err, _ := ValidateRequest(ctx, e.st, e.tenant, &req); err != nil {
		t.Fatal(err)
	}
	uri := e.push(t, e.tenant.ID, "spa", req.Params(), PARLifetime)
	rec := e.get(t, with(parQuery("spa", uri), "invitation", "evil", "organization", "evil", orglogin.InvitationIDParam, "evil"))
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, location(t, rec).Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["invitation"] != "" || txn.Params[orglogin.InvitationIDParam] != inv.ID || txn.Params[store.TxnParamOrgID] != o.ID {
		t.Fatal(txn.Params)
	}
}
func TestInvitationActionsDenialAfterAcceptance(t *testing.T) {
	a := newActionsEnv(t)
	e, o, inv := prepareInvitationEnv(t, a.env)
	ctx := context.Background()
	if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tenant.ID, ID: "tenant-role", Name: "tenant-role"}); err != nil {
		t.Fatal(err)
	}
	sess := e.session(t, e.login(t, fixedNow()))
	if err := e.st.RBAC().ChangeUserRoles(ctx, e.tenant.ID, sess.UserID, true, []string{"tenant-role"}); err != nil {
		t.Fatal(err)
	}
	otherOrg := addOrg(t, e.st, e.tenant.ID, "", "other-org", "")
	if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tenant.ID, ID: "other-role", Name: "other-role"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Organizations().AddMembers(ctx, e.tenant.ID, otherOrg.ID, []string{sess.UserID}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Organizations().ChangeMemberRoles(ctx, e.tenant.ID, otherOrg.ID, sess.UserID, true, []string{"other-role"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RBAC().ChangeRolePermissions(ctx, e.tenant.ID, "invited-role", true, []store.PermissionKey{{ResourceServerIdentifier: "https://api.acme.test", PermissionName: "read:things"}}); err != nil {
		t.Fatal(err)
	}
	a.postLogin(t, "deny", `if (!event.organization || event.organization.id !== "`+o.ID+`") throw new Error("missing org"); if (event.user.app_metadata.invited !== "value" || JSON.stringify([...event.authorization.roles].sort()) !== JSON.stringify(["invited-role","tenant-role"])) throw new Error("stale acceptance snapshot"); api.access.deny("denied after acceptance");`)
	rec := e.get(t, with(goodQuery(), "organization", o.ID, "invitation", "bearer"))
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, location(t, rec).Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.st.Users().Get(ctx, e.tenant.ID, sess.UserID)
	if err != nil {
		t.Fatal(err)
	}
	u.EmailVerified = true
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil)
	e.h.Resume(out, r, e.res(), txn, sess)
	if location(t, out).Query().Get("error") != "access_denied" || location(t, out).Query().Get("error_description") != "denied after acceptance" {
		t.Fatal(out.Header())
	}
	member, err := e.st.Organizations().IsMember(ctx, e.tenant.ID, o.ID, sess.UserID)
	if err != nil || !member {
		t.Fatal(member, err)
	}
	receipt, err := e.st.OrganizationsII().GetInvitationReceipt(ctx, e.tenant.ID, txn.ID)
	if err != nil || receipt.InvitationID != inv.ID {
		t.Fatal(receipt, err)
	}
	roles, err := e.st.Organizations().MemberRoles(ctx, e.tenant.ID, o.ID, sess.UserID, store.OrgPage{PerPage: 100})
	if err != nil || len(roles.Items) != 1 || roles.Items[0] != "invited-role" {
		t.Fatal(roles, err)
	}
	snapshot, err := store.OrganizationAuthorizationSnapshot(ctx, e.st, e.tenant.ID, sess.UserID, o.ID, "https://api.acme.test")
	if err != nil || len(snapshot.Permissions) != 1 || snapshot.Permissions[0] != "read:things" {
		t.Fatal(snapshot, err)
	}
	if a.runs(t) != 1 {
		t.Fatal("Action not run")
	}
	out = httptest.NewRecorder()
	e.h.Resume(out, r, e.res(), txn, sess)
	if location(t, out).Query().Get("code") != "" || a.runs(t) != 1 {
		t.Fatal("finished transaction replayed Actions or issued code")
	}
}

func TestInvitationForcedPrimaryConnection(t *testing.T) {
	e, o, inv := invitationEnv(t)
	ctx := context.Background()
	rec := e.get(t, with(goodQuery(), "organization", o.ID, "invitation", "bearer"))
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, location(t, rec).Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["connection"] != "Username-Password-Authentication" || txn.Params[orglogin.InvitationConnectionParam] != inv.ConnectionID {
		t.Fatal(txn.Params)
	}
	sess := e.session(t, e.login(t, fixedNow()))
	other := &store.Connection{TenantID: e.tenant.ID, ID: "other-connection", Name: "other-database", Strategy: "auth0", EnabledClients: []string{"spa"}}
	if err = e.st.Connections().Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	u, err := e.st.Users().Get(ctx, e.tenant.ID, sess.UserID)
	if err != nil {
		t.Fatal(err)
	}
	u.EmailVerified = true
	u.Identities = append(u.Identities, store.Identity{Connection: other.Name, Provider: "auth0", UserID: "linked"})
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	// The user's primary/linked identities never substitute for the actual
	// authentication connection recorded by the session.
	sess.ID = "other-session"
	sess.TokenHash = "other-session"
	sess.Connection = other.Name
	if err = e.st.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err = e.h.acceptInvitation(ctx, txn, sess); err == nil {
		t.Fatal("accepted alternate authenticated connection")
	}
	if _, err = e.st.OrganizationsII().GetInvitation(ctx, e.tenant.ID, o.ID, inv.ID); err != nil {
		t.Fatal(err)
	}
}

func TestInvitationCompletionClaimConcurrent(t *testing.T) {
	e, o, _ := invitationEnv(t)
	ctx := context.Background()
	rec := e.get(t, with(goodQuery(), "organization", o.ID, "invitation", "bearer"))
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, location(t, rec).Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	sess := e.session(t, e.login(t, fixedNow()))
	u, err := e.st.Users().Get(ctx, e.tenant.ID, sess.UserID)
	if err != nil {
		t.Fatal(err)
	}
	u.EmailVerified = true
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err = e.h.acceptInvitation(ctx, txn, sess); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- e.h.claimInvitationCompletion(ctx, txn, sess) }()
	}
	success := 0
	for i := 0; i < 2; i++ {
		if <-done == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("completion claims=%d", success)
	}
}

func TestInvitationCrossTenantTicket(t *testing.T) {
	e, o, inv := invitationEnv(t)
	ctx := context.Background()
	other := *e.tenant
	other.ID = "another-tenant"
	c, err := e.st.Clients().Get(ctx, e.tenant.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	req := Request{ClientID: c.ClientID, OrgMode: OrgFixed, OrgID: o.ID, Invitation: "bearer"}
	if err := bindInvitation(ctx, e.st, &other, c, &req); err == nil {
		t.Fatal("cross-tenant bearer resolved")
	}
	if _, err = e.st.OrganizationsII().GetInvitation(ctx, e.tenant.ID, o.ID, inv.ID); err != nil {
		t.Fatal("cross-tenant refusal consumed invitation", err)
	}
}

func TestInvitationSessionBindingRevision(t *testing.T) {
	e, o, _ := invitationEnv(t)
	ctx := context.Background()
	rec := e.get(t, with(goodQuery(), "organization", o.ID, "invitation", "bearer"))
	txn, err := e.st.AuthTransactions().Get(ctx, e.tenant.ID, location(t, rec).Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	old := txn.HostedState.Revision
	sess := e.session(t, e.login(t, fixedNow()))
	if err = e.h.bindInvitationSession(ctx, txn, sess); err != nil {
		t.Fatal(err)
	}
	if err = e.st.AuthTransactions().CompareAndSwapHosted(ctx, txn.TenantID, txn.ID, old, txn.HostedState, e.h.now()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale revision after session binding: %v", err)
	}
}
