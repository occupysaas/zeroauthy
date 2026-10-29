package mgmt_test

import (
	"bytes"
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"strings"
	"testing"
	"time"
)

func invitationEnv(t *testing.T) (*orgEnv, string) {
	e := newOrgEnv(t)
	e.caller = m2mCaller(append(orgScopes, allClientScopes...)...)
	e.h.Now = time.Now
	e.tn.SettingsExtra = map[string]any{"default_redirection_uri": "https://app.example/login?keep=yes"}
	if err := e.st.Tenants().Update(context.Background(), e.tn); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Clients().Create(context.Background(), &store.Client{TenantID: e.tn.ID, ClientID: "invite-client", Name: "Invites"}); err != nil {
		t.Fatal(err)
	}
	e.h.Actions = &actions.Engine{Store: e.st, Secrets: e.w}
	id := e.create(map[string]any{"name": "invites"}, 201)["id"].(string)
	return e, id
}
func invitationBody() map[string]any {
	return map[string]any{"inviter": map[string]any{"name": "Admin"}, "invitee": map[string]any{"email": "new@example.test"}, "client_id": "invite-client", "send_invitation_email": false}
}
func TestOrganizationInvitationCRUD(t *testing.T) {
	e, org := invitationEnv(t)
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	out := e.obj("POST", "/organizations/"+org+"/invitations", invitationBody(), post, 200)
	id := out["id"].(string)
	if out["ticket_id"] == id || out["invitation_url"] == "" {
		t.Fatal(out)
	}
	created, _ := time.Parse(time.RFC3339Nano, out["created_at"].(string))
	expires, _ := time.Parse(time.RFC3339Nano, out["expires_at"].(string))
	if expires.Sub(created) != 7*24*time.Hour {
		t.Fatal(out)
	}
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationInvitation(w, r, org, id) }
	if got := e.obj("GET", "/invitations/"+id, nil, get, 200); got["ticket_id"] != out["ticket_id"] {
		t.Fatal(got)
	}
	for _, ttl := range []any{nil, -1, 1.5, 2592001} {
		b := invitationBody()
		b["ttl_sec"] = ttl
		e.obj("POST", "/invitations", b, post, 400)
	}
	for _, ttl := range []int{0, 2592000} {
		b := invitationBody()
		b["ttl_sec"] = ttl
		e.obj("POST", "/invitations", b, post, 200)
	}
	for key, value := range map[string]any{"roles": []string{}, "client_id": "foreign-client", "connection_id": "con_foreign000000001"} {
		b := invitationBody()
		b[key] = value
		status := 404
		if key == "roles" {
			status = 400
		}
		e.obj("POST", "/invitations", b, post, status)
	}
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationInvitations(w, r, org) }
	got := e.obj("GET", "/invitations?include_totals=true", nil, list, 200)
	if _, ok := got["total"]; ok {
		t.Fatal(got)
	}
	if len(got["invitations"].([]any)) != 3 {
		t.Fatal(got)
	}
	del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationInvitation(w, r, org, id) }
	e.do(e.tn, "DELETE", "/invitations/"+id, nil, del, 204)
	e.do(e.tn, "DELETE", "/invitations/"+id, nil, del, 204)
	e.obj("GET", "/invitations/"+id, nil, get, 404)
}
func TestInvitationQueueFailureRollsBack(t *testing.T) {
	e, org := invitationEnv(t)
	e.h.Actions = nil
	b := invitationBody()
	b["send_invitation_email"] = true
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	e.obj("POST", "/invitations", b, post, 503)
	got, err := e.st.OrganizationsII().ListInvitations(context.Background(), e.tn.ID, org, store.OrgPage{PerPage: 100})
	if err != nil || len(got.Items) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
func TestOrganizationInvitationApplicationLoginURI(t *testing.T) {
	e, org := invitationEnv(t)
	created := e.obj("POST", "/clients", map[string]any{"name": "Invite application", "initiate_login_uri": "https://custom-app.example/login"}, e.h.CreateClient, 201)
	if created["initiate_login_uri"] != "https://custom-app.example/login" {
		t.Fatal(created)
	}
	b := invitationBody()
	b["client_id"] = created["client_id"]
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	out := e.obj("POST", "/invitations", b, post, 200)
	if !strings.HasPrefix(out["invitation_url"].(string), "https://custom-app.example/login?") {
		t.Fatal(out)
	}
}

func TestOrganizationInvitationDeliveryAndDisabledTemplate(t *testing.T) {
	e, org := invitationEnv(t)
	ctx := context.Background()
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	b := invitationBody()
	b["send_invitation_email"] = true
	out := e.obj("POST", "/invitations", b, post, 200)
	jobs, err := e.st.Actions().ClaimJobs(ctx, time.Now().Add(time.Hour), time.Minute, 100)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%v err=%v", jobs, err)
	}
	if bytes.Contains(jobs[0].Sealed, []byte(out["ticket_id"].(string))) || bytes.Contains(jobs[0].Sealed, []byte(out["invitation_url"].(string))) {
		t.Fatal("raw bearer in queue")
	}
	if err := e.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: e.tn.ID, Name: "user_invitation", Fields: map[string]any{"enabled": false}}, 0); err != nil {
		t.Fatal(err)
	}
	e.h.Actions = nil
	out = e.obj("POST", "/invitations", b, post, 200)
	if out["invitation_url"] == "" {
		t.Fatal(out)
	}
	jobs, err = e.st.Actions().ClaimJobs(ctx, time.Now().Add(time.Second), time.Minute, 100)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("disabled template enqueued: %v %v", jobs, err)
	}
}
func TestOrganizationInvitationExpiryAndIsolation(t *testing.T) {
	e, org := invitationEnv(t)
	ctx := context.Background()
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	e.h.Now = func() time.Time { return time.Now().Add(-8 * 24 * time.Hour) }
	out := e.obj("POST", "/invitations", invitationBody(), post, 200)
	id := out["id"].(string)
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationInvitation(w, r, org, id) }
	e.obj("GET", "/invitations/"+id, nil, get, 404)
	e.h.Now = time.Now
	out = e.obj("POST", "/invitations", invitationBody(), post, 200)
	id = out["id"].(string)
	e.do(e.sys, "GET", "/invitations/"+id, nil, get, 404)
	stored, err := e.st.OrganizationsII().GetInvitation(ctx, e.tn.ID, org, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.WrappedTicket, []byte(out["ticket_id"].(string))) || stored.TicketHash == out["ticket_id"] {
		t.Fatal("unsealed invitation")
	}
	if _, err := e.st.OrganizationsII().FindInvitation(ctx, e.sys.ID, stored.TicketHash); err != store.ErrNotFound {
		t.Fatal(err)
	}
}

type invitationQueueStore struct{ store.Store }
type invitationQueueActions struct{ store.Actions }

func (s invitationQueueStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(invitationQueueStore{tx}) })
}
func (s invitationQueueStore) Actions() store.Actions {
	return invitationQueueActions{s.Store.Actions()}
}
func (s invitationQueueActions) EnqueueJob(context.Context, *store.ActionJob) error {
	return errors.New("queue storage unavailable")
}
func TestInvitationQueueStorageFailureRollsBack(t *testing.T) {
	e, org := invitationEnv(t)
	e.h.Store = invitationQueueStore{e.st}
	b := invitationBody()
	b["send_invitation_email"] = true
	e.obj("POST", "/invitations", b, func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }, 500)
	got, err := e.st.OrganizationsII().ListInvitations(context.Background(), e.tn.ID, org, store.OrgPage{PerPage: 100})
	if err != nil || len(got.Items) != 0 {
		t.Fatalf("rollback %v %v", got, err)
	}
}
func TestOrganizationInvitationInvalidProvider(t *testing.T) {
	e, org := invitationEnv(t)
	if err := e.st.EmailProviders().Put(context.Background(), &store.EmailProvider{TenantID: e.tn.ID, Name: "smtp", Enabled: true, SealedCredentials: []byte("corrupt")}, 0); err != nil {
		t.Fatal(err)
	}
	b := invitationBody()
	b["send_invitation_email"] = true
	e.obj("POST", "/invitations", b, func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }, 503)
	got, err := e.st.OrganizationsII().ListInvitations(context.Background(), e.tn.ID, org, store.OrgPage{PerPage: 100})
	if err != nil || len(got.Items) != 0 {
		t.Fatalf("rollback %v %v", got, err)
	}
}
func TestOrganizationInvitationValidationReferences(t *testing.T) {
	e, org := invitationEnv(t)
	ctx := context.Background()
	if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tn.ID, ID: "rol_valid", Name: "Valid"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.sys.ID, ID: "rol_foreign", Name: "Foreign"}); err != nil {
		t.Fatal(err)
	}
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	for _, tc := range []struct {
		k      string
		v      any
		status int
	}{
		{"roles", []string{"rol_valid", "rol_foreign"}, 404},
		{"roles", []string{"rol_valid", "rol_missing"}, 404},
		{"roles", []string{""}, 400},
		{"user_metadata", []string{"bad"}, 400},
		{"app_metadata", map[string]any{"$bad": true}, 400},
		{"user_metadata", map[string]any{"big": strings.Repeat("x", identity.MetadataLimits.MaxBytes+1)}, 400},
		{"inviter", map[string]any{"name": strings.Repeat("x", 301)}, 400},
		{"invitee", map[string]any{"email": "Name <new@example.test>"}, 400},
		{"connection_id", nil, 400}, {"client_id", nil, 400}, {"send_invitation_email", nil, 400},
		{"inviter", map[string]any{"name": "Admin", "unknown": true}, 400},
	} {
		b := invitationBody()
		b[tc.k] = tc.v
		e.obj("POST", "/invitations", b, post, tc.status)
	}
	res, err := e.st.OrganizationsII().ListInvitations(ctx, e.tn.ID, org, store.OrgPage{PerPage: 100})
	if err != nil || len(res.Items) != 0 {
		t.Fatalf("invalid reference writes: %v %v", res, err)
	}
	b := invitationBody()
	b["roles"] = []string{"rol_valid", "rol_valid"}
	out := e.obj("POST", "/invitations", b, post, 200)
	if len(out["roles"].([]any)) != 1 {
		t.Fatal(out)
	}
}
func TestOrganizationInvitationURLConfiguration(t *testing.T) {
	e, org := invitationEnv(t)
	ctx := context.Background()
	post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
	e.tn.SettingsExtra = nil
	if err := e.st.Tenants().Update(ctx, e.tn); err != nil {
		t.Fatal(err)
	}
	e.obj("POST", "/invitations", invitationBody(), post, 400)
	e.tn.SettingsExtra = map[string]any{"default_redirection_uri": "http://app.example/login"}
	if err := e.st.Tenants().Update(ctx, e.tn); err != nil {
		t.Fatal(err)
	}
	e.obj("POST", "/invitations", invitationBody(), post, 400)
	e.tn.SettingsExtra = map[string]any{"default_redirection_uri": "https://app.example/login"}
	if err := e.st.Tenants().Update(ctx, e.tn); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.callWith(t, e.tn, e.caller, "POST", "/invitations", invitationBody(), http.Header{mgmt.CustomDomainHeader: []string{"foreign.example"}}, post)
	if rec.Code != 503 {
		t.Fatalf("foreign domain = %d", rec.Code)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "foreign.example", TenantID: e.sys.ID, Kind: store.HostPublic, DomainID: "cd_foreign", Active: true}); err != nil {
		t.Fatal(err)
	}
	c, err := e.st.Clients().Get(ctx, e.tn.ID, "invite-client")
	if err != nil {
		t.Fatal(err)
	}
	c.InitiateLoginURI = "https://foreign.example/login"
	if err := e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	e.obj("POST", "/invitations", invitationBody(), post, 400)
}
func TestOrganizationInvitationProjection(t *testing.T) {
	e, org := invitationEnv(t)
	out := e.obj("POST", "/invitations", invitationBody(), func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }, 200)
	id := out["id"].(string)
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationInvitation(w, r, org, id) }
	got := e.obj("GET", "/invitations?fields=id", nil, get, 200)
	if len(got) != 1 || got["id"] != id {
		t.Fatal(got)
	}
	e.obj("GET", "/invitations?fields=secret", nil, get, 400)
	e.obj("GET", "/invitations?unknown=yes", nil, get, 400)
}
func TestOrganizationInvitationClientLoginURIPatch(t *testing.T) {
	e, _ := invitationEnv(t)
	c := e.obj("POST", "/clients", map[string]any{"name": "Login URI", "initiate_login_uri": "https://app.example/login"}, e.h.CreateClient, 201)
	id := c["client_id"].(string)
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) }
	c = e.obj("PATCH", "/clients/"+id, map[string]any{"name": "Renamed"}, patch, 200)
	if c["initiate_login_uri"] != "https://app.example/login" {
		t.Fatal(c)
	}
	for _, v := range []any{nil, "http://app.example/login", "https://user:pass@app.example/login"} {
		e.obj("PATCH", "/clients/"+id, map[string]any{"initiate_login_uri": v}, patch, 400)
	}
}

type noOrganizationsIIStore struct{ store.Store }

func (noOrganizationsIIStore) CheckOrganizationsIISupport(context.Context) error {
	return store.ErrOrganizationsIIUnavailable
}
func (noOrganizationsIIStore) OrganizationsIISupported() bool { return false }
func TestOrganizationInvitationOldPluginFailsClosed(t *testing.T) {
	e, org := invitationEnv(t)
	e.h.Store = noOrganizationsIIStore{e.st}
	for _, handler := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) },
		func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationInvitations(w, r, org) },
		func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationInvitation(w, r, org, "uinv_missing") },
		func(w http.ResponseWriter, r *http.Request) {
			e.h.DeleteOrganizationInvitation(w, r, org, "uinv_missing")
		},
	} {
		e.obj("GET", "/invitations", nil, handler, 501)
	}
}

// Unsupported query parameters must not change invitations or enqueue mail.
func TestOrganizationInvitationMutationQueryRejected(t *testing.T) {
	for _, query := range []string{"?unknown=yes", "?unknown=yes&unknown=again", "?page=0"} {
		t.Run(query, func(t *testing.T) {
			e, org := invitationEnv(t)
			ctx := context.Background()
			post := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationInvitation(w, r, org) }
			body := invitationBody()
			body["send_invitation_email"] = true
			rec, _ := e.call(t, e.tn, e.caller, "POST", "/invitations"+query, body, post)
			if rec.Code != 400 {
				t.Errorf("POST unsupported query status=%d, want 400", rec.Code)
			}
			invitations, err := e.st.OrganizationsII().ListInvitations(ctx, e.tn.ID, org, store.OrgPage{PerPage: 100})
			if err != nil {
				t.Fatal(err)
			}
			if len(invitations.Items) != 0 {
				t.Errorf("rejected POST stored %d invitations", len(invitations.Items))
			}
			jobs, err := e.st.Actions().ClaimJobs(ctx, time.Now().Add(time.Hour), time.Minute, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != 0 {
				t.Errorf("rejected POST queued %d jobs", len(jobs))
			}
			target := e.obj("POST", "/invitations", invitationBody(), post, 200)["id"].(string)
			del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationInvitation(w, r, org, target) }
			rec, _ = e.call(t, e.tn, e.caller, "DELETE", "/invitations/"+target+query, nil, del)
			if rec.Code != 400 {
				t.Errorf("DELETE unsupported query status=%d, want 400", rec.Code)
			}
			if _, err := e.st.OrganizationsII().GetInvitation(ctx, e.tn.ID, org, target); err != nil {
				t.Errorf("rejected DELETE changed target: %v", err)
			}
		})
	}
}
