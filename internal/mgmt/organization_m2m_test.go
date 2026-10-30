package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"testing"
)

func TestOrganizationM2MGrantCRUD(t *testing.T) {
	e := newCGEnv(t)
	out := e.mustCreate(t, map[string]any{"client_id": e.client, "audience": ordersAPI, "scope": []string{"read:orders"}, "organization_usage": "allow", "allow_any_organization": true})
	id := out["id"].(string)
	if out["organization_usage"] != "allow" || out["allow_any_organization"] != true {
		t.Fatal(out)
	}
	rec, out := e.patch(t, id, map[string]any{"scope": []string{"write:orders"}})
	if rec.Code != 200 || out["organization_usage"] != "allow" || out["allow_any_organization"] != true {
		t.Fatalf("preserve: %d %v", rec.Code, out)
	}
	for _, body := range []map[string]any{{"organization_usage": nil}, {"allow_any_organization": nil}, {"organization_usage": "invalid"}, {"allow_any_organization": "true"}} {
		rec, _ := e.patch(t, id, body)
		if rec.Code != 400 {
			t.Fatalf("bad patch %v: %d", body, rec.Code)
		}
	}
	rec, out = e.patch(t, id, map[string]any{"organization_usage": "deny", "allow_any_organization": false})
	if rec.Code != 200 || out["organization_usage"] != "deny" || out["allow_any_organization"] != false {
		t.Fatalf("clear %d %v", rec.Code, out)
	}
	for _, body := range []map[string]any{{"organization_usage": "allow"}, {"allow_any_organization": true}} {
		body["client_id"] = e.client
		body["audience"] = ordersAPI
		body["subject_type"] = "user"
		body["scope"] = []string{}
		rec, _ := e.create(t, body)
		if rec.Code != 400 {
			t.Fatalf("user active: %d", rec.Code)
		}
	}
}

func TestOrganizationM2MAssociations(t *testing.T) {
	e := newOrgEnv(t)
	ctx := context.Background()
	org := e.create(map[string]any{"name": "machine"}, 201)["id"].(string)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(e.st.Clients().Create(ctx, &store.Client{TenantID: e.tn.ID, ClientID: "machine", IsFirstParty: true}))
	g := &store.ClientGrant{TenantID: e.tn.ID, ID: "cgr_machine", ClientID: "machine", Audience: "https://api.test", SubjectType: store.SubjectTypeClient, Scopes: []string{"read"}, OrganizationUsage: "allow"}
	must(e.st.ClientGrants().Create(ctx, g))
	post := func(w http.ResponseWriter, r *http.Request) { e.h.AssociateOrganizationClientGrant(w, r, org) }
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClientGrants(w, r, org) }
	reverse := func(w http.ResponseWriter, r *http.Request) { e.h.ListClientGrantOrganizations(w, r, g.ID) }
	del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationClientGrant(w, r, org, g.ID) }
	missing := e.obj("POST", "/", `{"grant_id":"cgr_missing"}`, post, 404)
	if missing["errorCode"] != "not_found" {
		t.Fatal(missing)
	}
	for _, body := range []string{`{}`, `{"grant_id":null}`, `{"grant_id":"cgr_machine","scope":["write"]}`} {
		e.do(e.tn, "POST", "/", body, post, 400)
	}
	for _, query := range []string{"?take=1", "?audience=x", "?client_id=machine", "?grant_ids=x", "?page=0&page=1"} {
		e.do(e.tn, "GET", "/"+query, nil, list, 400)
	}
	e.do(e.tn, "POST", "/?unknown=yes", `{"grant_id":"cgr_machine"}`, post, 400)
	e.do(e.tn, "POST", "/", `{"grant_id":"cgr_machine"}`, post, 201)
	e.do(e.tn, "POST", "/", `{"grant_id":"cgr_machine"}`, post, 409)
	got := e.obj("GET", "/?include_totals=true", nil, list, 200)
	if got["total"] != float64(1) {
		t.Fatal(got)
	}
	if got := e.obj("GET", "/?take=1", nil, reverse, 200); len(got["organizations"].([]any)) != 1 {
		t.Fatal(got)
	}
	g.Scopes = []string{"changed"}
	must(e.st.ClientGrants().Update(ctx, g))
	got = e.obj("GET", "/?include_totals=true", nil, list, 200)
	if got["client_grants"].([]any)[0].(map[string]any)["scope"].([]any)[0] != "changed" {
		t.Fatal("copied scope", got)
	}
	e.do(e.tn, "DELETE", "/?unknown=yes", nil, del, 400)
	e.do(e.tn, "DELETE", "/", nil, del, 204)
	e.do(e.tn, "DELETE", "/", nil, del, 404)
}

func TestOrganizationM2MGrantFilter(t *testing.T) {
	e := newCGEnv(t)
	e.mustCreate(t, map[string]any{"client_id": e.client, "audience": ordersAPI, "scope": []string{}, "allow_any_organization": true})
	e.mustCreate(t, map[string]any{"client_id": e.newClient(t), "audience": ordersAPI, "scope": []string{}})
	for _, v := range []string{"true", "false"} {
		rec, out := e.list(t, "?allow_any_organization="+v)
		items, ok := out.([]any)
		if rec.Code != 200 || !ok || len(items) != 1 || items[0].(map[string]any)["allow_any_organization"] != (v == "true") {
			t.Fatalf("filter %s: %d %v", v, rec.Code, out)
		}
	}
	for _, q := range []string{"?allow_any_organization=yes", "?allow_any_organization=", "?allow_any_organization=true&allow_any_organization=false"} {
		rec, _ := e.list(t, q)
		if rec.Code != 400 {
			t.Fatalf("bad filter %s: %d", q, rec.Code)
		}
	}
}

func TestOrganizationM2MOldPlugin(t *testing.T) {
	e := newCGEnv(t)
	out := e.grant(t, "read:orders")
	id := out["id"].(string)
	e.h.Store = noOrganizationsIIStore{e.st}
	rec, _ := e.patch(t, id, map[string]any{"organization_usage": "allow"})
	if rec.Code != 501 {
		t.Fatalf("active patch %d", rec.Code)
	}
	rec, _ = e.patch(t, id, map[string]any{"allow_any_organization": true})
	if rec.Code != 501 {
		t.Fatalf("active any %d", rec.Code)
	}
	rec, _ = e.patch(t, id, map[string]any{"organization_usage": "deny", "allow_any_organization": false})
	if rec.Code != 200 {
		t.Fatalf("inert patch %d", rec.Code)
	}
	rec, _ = e.create(t, map[string]any{"client_id": e.newClient(t), "audience": ordersAPI, "scope": []string{}, "organization_usage": "require"})
	if rec.Code != 501 {
		t.Fatalf("active create %d", rec.Code)
	}
}

func TestOrganizationM2MStrictAssociationReads(t *testing.T) {
	e := newOrgEnv(t)
	org := e.create(map[string]any{"name": "strict-grants"}, 201)["id"].(string)
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClientGrants(w, r, org) }
	e.do(e.tn, "GET", "/", `{}`, list, 400)
}
