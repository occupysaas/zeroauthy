package login

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOrganizationPasswordChangeContext(t *testing.T) {
	for _, scenario := range []string{"valid", "deleted", "disabled", "client disabled", "foreign org"} {
		t.Run(scenario, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			org, conn, user := organizationFixture(t, e, "no_prompt", true, true)
			user.Identities = append(user.Identities, store.Identity{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: "secondary", PasswordHash: "secondary-hash", ProfileData: map[string]any{"email": "secondary@example.test"}})
			if err := e.st.Users().Update(ctx, user); err != nil {
				t.Fatal(err)
			}
			logo := "https://assets.example.test/reset-org.png"
			org.Branding = &store.OrgBranding{LogoURL: &logo}
			if err := e.st.Organizations().Update(ctx, org); err != nil {
				t.Fatal(err)
			}
			raw, err := dbconn.IssueResetTicket(ctx, e.st, store.PasswordResetTicket{TenantID: org.TenantID, UserID: user.UserID, Connection: conn.Name, ClientID: "spa", OrganizationID: org.ID}, 43, fixedNow(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			b := e.browser("acme.example.test")
			page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
			if page.Code != 200 || !strings.Contains(page.Body.String(), logo) {
				t.Fatalf("missing branding: %d %s", page.Code, page.Body)
			}
			csrf := csrfField.FindStringSubmatch(page.Body.String())
			if len(csrf) != 2 {
				t.Fatal("no csrf")
			}
			switch scenario {
			case "deleted":
				err = e.st.Organizations().Delete(ctx, org.TenantID, org.ID)
			case "client disabled":
				conn.EnabledClients = nil
				err = e.st.Connections().Update(ctx, conn)
			case "foreign org":
				err = e.st.Organizations().Delete(ctx, org.TenantID, org.ID)
				if err == nil {
					err = e.st.Tenants().Create(ctx, &store.Tenant{ID: "foreign", Name: "foreign"})
				}
				if err == nil {
					copy := *org
					copy.TenantID = "foreign"
					err = e.st.Organizations().Create(ctx, &copy, nil)
				}
			case "disabled":
				link, e2 := e.st.Organizations().GetConnection(ctx, org.TenantID, org.ID, conn.ID)
				if e2 != nil {
					t.Fatal(e2)
				}
				link.IsEnabled = false
				link.IsEnabledSet = true
				err = e.st.Organizations().PutConnection(ctx, *link, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"ticket": {raw}, "csrf": {csrf[1]}, "password": {"new password 123"}, "password_confirm": {"new password 123"}}
			rec := b.do(t, "POST", "/u/reset-password", form)
			want := 200
			if scenario != "valid" {
				want = 400
			}
			if rec.Code != want {
				t.Fatalf("completion %d want %d: %s", rec.Code, want, rec.Body)
			}
			after, e2 := e.st.Users().Get(ctx, org.TenantID, user.UserID)
			if e2 != nil || after.UserID != user.UserID || len(after.Identities) != 2 || after.Identities[1].PasswordHash != "secondary-hash" {
				t.Fatalf("identity changed: %+v %v", after, e2)
			}
			if scenario != "valid" && after.Identities[0].PasswordHash != user.Identities[0].PasswordHash {
				t.Fatal("invalid context changed password")
			}
			if scenario == "valid" {
				if rec = b.do(t, "POST", "/u/reset-password", form); rec.Code != 400 {
					t.Fatal("ticket reusable")
				}
				member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
				if err != nil || member {
					t.Fatalf("membership changed %v %v", member, err)
				}
			}
		})
	}
}

// Revocation after ticket consumption must still stop the password write.
type resetRevocationStore struct {
	store.Store
	organizationID, connectionID string
	revoked                      bool
}

func (s *resetRevocationStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(resetRevocationTx{Store: tx, owner: s}) })
}

type resetRevocationTx struct {
	store.Store
	owner *resetRevocationStore
}

func (s resetRevocationTx) PasswordResetTickets() store.PasswordResetTickets {
	return resetRevocationTickets{PasswordResetTickets: s.Store.PasswordResetTickets(), tx: s}
}

type resetRevocationTickets struct {
	store.PasswordResetTickets
	tx resetRevocationTx
}

func (s resetRevocationTickets) Consume(ctx context.Context, tid, hash string, at time.Time) (*store.PasswordResetTicket, error) {
	tk, err := s.PasswordResetTickets.Consume(ctx, tid, hash, at)
	if err != nil {
		return nil, err
	}
	if !s.tx.owner.revoked {
		link, e := s.tx.Organizations().GetConnection(ctx, tid, s.tx.owner.organizationID, s.tx.owner.connectionID)
		if e != nil {
			return nil, e
		}
		link.IsEnabled = false
		link.IsEnabledSet = true
		if e = s.tx.Organizations().PutConnection(ctx, *link, false); e != nil {
			return nil, e
		}
		s.tx.owner.revoked = true
	}
	return tk, nil
}
func TestOrganizationPasswordChangeContextMutationRecheck(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	org, conn, user := organizationFixture(t, e, "no_prompt", true, true)
	raw, err := dbconn.IssueResetTicket(ctx, e.st, store.PasswordResetTicket{TenantID: org.TenantID, UserID: user.UserID, Connection: conn.Name, ClientID: "spa", OrganizationID: org.ID}, 43, fixedNow(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
	e.h.Store = &resetRevocationStore{Store: e.st, organizationID: org.ID, connectionID: conn.ID}
	rec := submit(t, b, page, raw, "new password 123")
	if rec.Code != 400 {
		t.Fatalf("revoked policy changed password: %d %s", rec.Code, rec.Body)
	}
	after, err := e.st.Users().Get(ctx, org.TenantID, user.UserID)
	if err != nil || after.Identities[0].PasswordHash != user.Identities[0].PasswordHash {
		t.Fatal("password changed after revocation")
	}
}

func TestOrganizationPasswordChangeContextActions(t *testing.T) {
	re := newResetActionsEnv(t)
	ctx := context.Background()
	org, conn, user := organizationFixture(t, re.env, "no_prompt", true, true)
	first := re.a.Deploy(t, org.TenantID, actions.TriggerResetPostChallenge, "mutate-reset-context", `exports.onExecutePostChallenge=(event)=>{if(event.organization.id!=='`+org.ID+`')throw Error('missing org');event.organization.id='forged';event.user.app_metadata.organization_id='forged';};`)
	second := re.a.Deploy(t, org.TenantID, actions.TriggerResetPostChallenge, "verify-reset-context", `exports.onExecutePostChallenge=(event,api)=>{if(event.organization.id!=='`+org.ID+`')throw Error('replaced org');api.transaction.setResultUrl('https://app.acme.test/done');};`)
	re.a.Bind(t, org.TenantID, actions.TriggerResetPostChallenge, first, second)
	raw, err := dbconn.IssueResetTicket(ctx, re.st, store.PasswordResetTicket{TenantID: org.TenantID, UserID: user.UserID, Connection: conn.Name, ClientID: "spa", OrganizationID: org.ID}, 43, fixedNow(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := re.browser("acme.example.test")
	page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
	if page.Code != 200 {
		t.Fatalf("action context %d %s", page.Code, page.Body)
	}
	rec := submit(t, b, page, raw, "new password 123")
	if rec.Code != 302 || !strings.HasPrefix(rec.Header().Get("Location"), "https://app.acme.test/done") {
		t.Fatalf("reset action result %d %s", rec.Code, rec.Body)
	}
}

type resetNoEnrollmentStore struct {
	store.Store
	writes int
}

func (s *resetNoEnrollmentStore) Organizations() store.Organizations {
	return resetNoEnrollmentOrgs{Organizations: s.Store.Organizations(), owner: s}
}
func (s *resetNoEnrollmentStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(resetNoEnrollmentTx{Store: tx, owner: s}) })
}

type resetNoEnrollmentTx struct {
	store.Store
	owner *resetNoEnrollmentStore
}

func (s resetNoEnrollmentTx) Organizations() store.Organizations {
	return resetNoEnrollmentOrgs{Organizations: s.Store.Organizations(), owner: s.owner}
}

type resetNoEnrollmentOrgs struct {
	store.Organizations
	owner *resetNoEnrollmentStore
}

func (s resetNoEnrollmentOrgs) AddMembers(ctx context.Context, tid, org string, users []string) error {
	s.owner.writes++
	return s.Organizations.AddMembers(ctx, tid, org, users)
}
func (s resetNoEnrollmentOrgs) ChangeMemberRoles(ctx context.Context, tid, org, user string, add bool, roles []string) error {
	s.owner.writes++
	return s.Organizations.ChangeMemberRoles(ctx, tid, org, user, add, roles)
}
func TestOrganizationPasswordChangeContextHostedRequest(t *testing.T) {
	e := newEnv(t)
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
	spy := &resetNoEnrollmentStore{Store: e.st}
	e.h.Store = spy
	e.h.Resets.Store = spy
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "organization", org.ID)
	unknown := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"nobody@acme.test"}})
	known := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"alice@acme.test"}})
	if unknown.Code != 200 || known.Code != 200 || stripNonce(unknown.Body.String()) != stripNonce(known.Body.String()) {
		t.Fatal("organization reset leaks account existence")
	}
	raw := resetLink(t, e)
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), org.TenantID, secrets.HashToken(raw))
	if err != nil || tk.OrganizationID != org.ID {
		t.Fatalf("hosted context lost %+v %v", tk, err)
	}
	page := b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
	rec := submit(t, b, page, raw, "new password 123")
	if rec.Code != 200 {
		t.Fatalf("hosted reset %d %s", rec.Code, rec.Body)
	}
	if spy.writes != 0 {
		t.Fatalf("reset performed %d membership/role writes", spy.writes)
	}
}
