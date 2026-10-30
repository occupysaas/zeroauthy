package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"testing"
)

func TestOrganizationClientAssociations(t *testing.T) {
	e := newOrgEnv(t)
	ctx := context.Background()
	o := &store.Organization{TenantID: e.tn.ID, ID: "org_0000000000000001", Name: "entitlement", DisplayName: "Entitlement"}
	if err := e.st.Organizations().Create(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	c := &store.Client{TenantID: e.tn.ID, ClientID: "client", Name: "app"}
	if err := e.st.Clients().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	post := func(w http.ResponseWriter, r *http.Request) { e.h.AssociateOrganizationClients(w, r, o.ID) }
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClients(w, r, o.ID) }
	e.do(e.tn, "POST", "/", `{"clients":[{"client_id":"client","use_for_member_access":true},{"client_id":"missing","use_for_member_access":true}]}`, post, 404)
	out := e.obj("GET", "/", nil, list, 200)
	if len(out["clients"].([]any)) != 0 {
		t.Fatal("partial batch")
	}
	e.do(e.tn, "POST", "/", `{"clients":[{"client_id":"client","use_for_member_access":true}]}`, post, 201)
	out = e.obj("GET", "/", nil, list, 200)
	summary := out["clients"].([]any)[0].(map[string]any)["client"].(map[string]any)
	for _, key := range []string{"client_secret", "secret_hash", "SecretHash"} {
		if _, ok := summary[key]; ok {
			t.Fatalf("secret: %v", summary)
		}
	}
	e.do(e.tn, "POST", "/", `{"clients":[{"client_id":"client","use_for_member_access":false}]}`, post, 409)
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganizationClient(w, r, o.ID, "client") }
	e.do(e.tn, "PATCH", "/", `{}`, patch, 200)
	e.do(e.tn, "PATCH", "/", `{"use_for_member_access":null}`, patch, 400)
	orgs := e.list("/?include_client_association_for=client", e.h.ListOrganizations)
	if orgs[0].(map[string]any)["client"].(map[string]any)["use_for_member_access"] != true {
		t.Fatal(orgs)
	}
	orgs = e.list("/?include_client_association_for=missing", e.h.ListOrganizations)
	if _, ok := orgs[0].(map[string]any)["client"]; ok {
		t.Fatal("absent annotation present")
	}
}

func TestOrganizationClientAssociationsStrictBodiesAndQueries(t *testing.T) {
	e := newOrgEnv(t)
	ctx := context.Background()
	o := &store.Organization{TenantID: e.tn.ID, ID: "org_0000000000000001", Name: "strict"}
	if err := e.st.Organizations().Create(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Clients().Create(ctx, &store.Client{TenantID: e.tn.ID, ClientID: "client", Secrets: []store.ClientSecret{{Hash: "SECRET"}}}); err != nil {
		t.Fatal(err)
	}
	post := func(w http.ResponseWriter, r *http.Request) { e.h.AssociateOrganizationClients(w, r, o.ID) }
	del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationClients(w, r, o.ID) }
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganizationClient(w, r, o.ID, "client") }
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClients(w, r, o.ID) }
	for _, body := range []string{`{}`, `{"clients":null}`, `{"clients":[]}`, `{"clients":[{"client_id":"client"}]}`, `{"clients":[{"client_id":"client","use_for_member_access":null}]}`, `{"clients":[{"client_id":"client","use_for_member_access":"true"}]}`, `{"clients":[{"client_id":"client","use_for_member_access":true,"secret":"x"}]}`, `{"clients":[{"client_id":"client","use_for_member_access":true}],"extra":true}`} {
		e.do(e.tn, "POST", "/", body, post, 400)
	}
	for _, query := range []string{"?unknown=yes", "?unknown=yes&unknown=no", "?page=0"} {
		e.do(e.tn, "POST", "/"+query, `{"clients":[{"client_id":"client","use_for_member_access":true}]}`, post, 400)
	}
	if _, err := e.st.OrganizationsII().GetClient(ctx, e.tn.ID, o.ID, "client"); err != store.ErrNotFound {
		t.Fatalf("rejected write persisted: %v", err)
	}
	e.do(e.tn, "PATCH", "/", `{"use_for_member_access":true}`, patch, 404)
	e.do(e.tn, "POST", "/", `{"clients":[{"client_id":"client","use_for_member_access":true}]}`, post, 201)
	for _, query := range []string{"?unknown=yes", "?take=1&take=2", "?page=0", "?take=0", "?take=101"} {
		e.do(e.tn, "GET", "/"+query, nil, list, 400)
	}
	for _, query := range []string{"?unknown=yes", "?unknown=yes&unknown=no", "?page=0"} {
		e.do(e.tn, "DELETE", "/"+query, `{"clients":["client"]}`, del, 400)
	}
	if _, err := e.st.OrganizationsII().GetClient(ctx, e.tn.ID, o.ID, "client"); err != nil {
		t.Fatal("rejected delete removed target", err)
	}
	e.do(e.tn, "DELETE", "/", `{"clients":["client","missing"]}`, del, 404)
	if _, err := e.st.OrganizationsII().GetClient(ctx, e.tn.ID, o.ID, "client"); err != nil {
		t.Fatal("partial delete", err)
	}
	e.do(e.tn, "DELETE", "/", `{"clients":["client"]}`, del, 204)
}

func TestOrganizationMemberEntitlementCRUD(t *testing.T) {
	e := newOrgEnv(t)
	o := e.create(map[string]any{"name": "active", "is_app_entitlement_active": true}, 201)
	id := o["id"].(string)
	if o["is_app_entitlement_active"] != true {
		t.Fatal(o)
	}
	if got := e.obj("GET", "/", nil, e.get(id), 200); got["is_app_entitlement_active"] != true {
		t.Fatal(got)
	}
	if got := e.obj("PATCH", "/", map[string]any{"display_name": "Still active"}, e.patch(id), 200); got["is_app_entitlement_active"] != true {
		t.Fatal(got)
	}
	e.obj("PATCH", "/", map[string]any{"is_app_entitlement_active": nil}, e.patch(id), 400)
	if got := e.obj("PATCH", "/", map[string]any{"is_app_entitlement_active": false}, e.patch(id), 200); got["is_app_entitlement_active"] != false {
		t.Fatal(got)
	}
	e.h.Store = noOrganizationsIIStore{e.st}
	e.create(map[string]any{"name": "legacy"}, 201)
	e.obj("PATCH", "/", map[string]any{"is_app_entitlement_active": false}, e.patch(id), 200)
	e.create(map[string]any{"name": "legacy-active", "is_app_entitlement_active": true}, 501)
	e.obj("PATCH", "/", map[string]any{"is_app_entitlement_active": true}, e.patch(id), 501)
}
