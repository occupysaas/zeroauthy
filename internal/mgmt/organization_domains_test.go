package mgmt_test

import (
	"context"
	"net/http"
	"testing"
)

func TestOrganizationDiscoveryDomains(t *testing.T) {
	e := newOrgEnv(t)
	org := e.create(map[string]any{"name": "discovery"}, 201)["id"].(string)
	create := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationDiscoveryDomain(w, r, org) }
	// Handler calls bypass route scope enforcement; generated adapters enforce scopes.
	d := e.obj("POST", "/domains", map[string]any{"domain": "EXAMPLE.COM"}, create, 201)
	id := d["id"].(string)
	if d["domain"] != "example.com" || d["status"] != "pending" || d["use_for_organization_discovery"] != true || d["verification_host"] != "_zeroauthy-org.example.com" || d["verification_txt"] == "" {
		t.Fatalf("bad domain: %v", d)
	}
	e.obj("POST", "/domains", map[string]any{"domain": "example.com"}, create, 409)
	for _, body := range []any{map[string]any{"domain": "x.com", "status": "verified"}, map[string]any{"domain": "x.com", "status": nil}, map[string]any{"domain": "x.com", "unknown": true}, map[string]any{"domain": "*.x.com"}} {
		e.obj("POST", "/domains", body, create, 400)
	}
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationDiscoveryDomain(w, r, org, id) }
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganizationDiscoveryDomain(w, r, org, id) }
	d = e.obj("PATCH", "/domains", map[string]any{"status": "verified", "use_for_organization_discovery": false}, patch, 200)
	if d["status"] != "verified" || d["use_for_organization_discovery"] != false {
		t.Fatal(d)
	}
	for _, body := range []any{map[string]any{"status": nil}, map[string]any{"domain": "changed.com"}, map[string]any{"use_for_organization_discovery": nil}} {
		e.obj("PATCH", "/domains", body, patch, 400)
	}
	e.obj("GET", "/domains?take=1", nil, get, 400)
	named := func(w http.ResponseWriter, r *http.Request) {
		e.h.GetOrganizationDiscoveryDomainByName(w, r, org, "EXAMPLE.COM")
	}
	if got := e.obj("GET", "/domains/name", nil, named, 200); got["id"] != id {
		t.Fatal(got)
	}
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationDiscoveryDomains(w, r, org) }
	for _, query := range []string{"?take=1&take=2", "?page=0", "?take=0", "?take=101"} {
		e.obj("GET", "/domains"+query, nil, list, 400)
	}
	got := e.obj("GET", "/domains?take=1", nil, list, 200)
	if len(got["domains"].([]any)) != 1 {
		t.Fatal(got)
	}
	other := e.create(map[string]any{"name": "otherdiscovery"}, 201)["id"].(string)
	e.obj("POST", "/domains", map[string]any{"domain": "example.com"}, func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationDiscoveryDomain(w, r, other) }, 201)
	e.obj("GET", "/domains", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationDiscoveryDomain(w, r, other, id) }, 404)
	e.do(e.tn, "DELETE", "/domains", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationDiscoveryDomain(w, r, org, id) }, 204)
	e.obj("GET", "/domains", nil, get, 404)
	if _, err := e.st.Organizations().Get(context.Background(), e.tn.ID, org); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationDiscoveryMalformedQueries(t *testing.T) {
	e := newOrgEnv(t)
	org := e.create(map[string]any{"name": "malformedqueries"}, 201)["id"].(string)
	create := func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationDiscoveryDomain(w, r, org) }
	d := e.obj("POST", "/domains", map[string]any{"domain": "example.com"}, create, 201)
	id := d["id"].(string)
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationDiscoveryDomain(w, r, org, id) }
	list := func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationDiscoveryDomains(w, r, org) }
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganizationDiscoveryDomain(w, r, org, id) }
	del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganizationDiscoveryDomain(w, r, org, id) }
	named := func(w http.ResponseWriter, r *http.Request) {
		e.h.GetOrganizationDiscoveryDomainByName(w, r, org, "example.com")
	}
	for _, query := range []string{"?unknown=%zz", "?take=1&take=%zz", "?unknown=bad;value"} {
		e.obj("GET", "/domains"+query, nil, list, 400)
		e.obj("GET", "/domains"+query, nil, get, 400)
		e.obj("GET", "/domains"+query, nil, named, 400)
		e.obj("POST", "/domains"+query, map[string]any{"domain": "new.example.com"}, create, 400)
		e.obj("PATCH", "/domains"+query, map[string]any{"status": "verified"}, patch, 400)
		e.obj("DELETE", "/domains"+query, nil, del, 400)
		if got := e.obj("GET", "/domains", nil, get, 200); got["status"] != "pending" {
			t.Fatalf("malformed PATCH mutated state: %v", got)
		}
		got := e.obj("GET", "/domains", nil, list, 200)
		if len(got["domains"].([]any)) != 1 {
			t.Fatalf("malformed POST mutated state: %v", got)
		}
	}
}
