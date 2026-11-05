package mgmt_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestRPIDCustomDomainWrites(t *testing.T) {
	e := newUsersEnv(t)
	e.h.BaseDomain = "id.example.com"
	e.h.Domains = customdomain.NewService(e.st, nil, customdomain.ServiceConfig{BaseDomain: e.h.BaseDomain, ManagedEnabled: true}, time.Now, rand.Reader)
	create := func(host, rp string) (int, map[string]any) {
		rec, out := e.callWith(t, e.tn, m2mCaller("create:custom_domains"), "POST", "/api/v2/custom-domains", map[string]any{"domain": host, "type": "auth0_managed_certs", "relying_party_identifier": rp}, nil, e.h.CreateCustomDomain)
		m, _ := out.(map[string]any)
		return rec.Code, m
	}
	code, out := create("login.example.com", "example.com")
	if code != 201 {
		t.Fatalf("default policy = %d %v", code, out)
	}
	id := out["custom_domain_id"].(string)
	e.h.RestrictSharedRPIDs = true
	if code, out := create("other.example.com", "example.com"); code != 400 || out["errorCode"] != "invalid_body" {
		t.Fatalf("strict POST = %d %v", code, out)
	}
	rec, outAny := e.callWith(t, e.tn, m2mCaller("update:custom_domains"), "PATCH", "/api/v2/custom-domains/"+id, map[string]any{"relying_party_identifier": "example.com"}, nil, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateCustomDomain(w, r, id) })
	if rec.Code != 400 || outAny.(map[string]any)["errorCode"] != "invalid_body" {
		t.Fatalf("strict PATCH = %d %s", rec.Code, rec.Body)
	}
	// Clearing the override restores the domain's own RP ID even in strict mode.
	rec, _ = e.callWith(t, e.tn, m2mCaller("update:custom_domains"), "PATCH", "/api/v2/custom-domains/"+id, map[string]any{"relying_party_identifier": nil}, nil, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateCustomDomain(w, r, id) })
	if rec.Code != 200 {
		t.Fatalf("clear = %d %s", rec.Code, rec.Body)
	}
	if err := e.st.CustomDomains().PutHost(context.Background(), &store.HostBinding{Host: "child.login.example.com:9543", TenantID: e.sys.ID, Kind: store.HostOperator, Active: true}); err != nil {
		t.Fatal(err)
	}
	rec, _ = e.callWith(t, e.tn, m2mCaller("update:custom_domains"), "PATCH", "/api/v2/custom-domains/"+id, map[string]any{"relying_party_identifier": nil}, nil, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateCustomDomain(w, r, id) })
	if rec.Code != 400 {
		t.Fatalf("null RP ID covers another tenant's ported host = %d %s", rec.Code, rec.Body)
	}
	for _, rp := range []string{"co.uk", "elsewhere.test"} {
		if code, _ := create("bad.example.com", rp); code != 400 {
			t.Errorf("invalid RP ID %q = %d", rp, code)
		}
	}
	e.h.BaseDomain = "unrelated.test"
	if err := e.st.CustomDomains().PutHost(context.Background(), &store.HostBinding{Host: "foreign.shared.example", TenantID: e.sys.ID, Kind: store.HostOperator, Active: true}); err != nil {
		t.Fatal(err)
	}
	if code, out := create("login.shared.example", "shared.example"); code != 400 || out["errorCode"] != "invalid_body" {
		t.Fatalf("foreign host POST = %d %v", code, out)
	}
}
