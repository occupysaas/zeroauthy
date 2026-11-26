package myorg

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// fakeDNS answers TXT lookups from a table; err applies to every lookup.
type fakeDNS struct {
	txt map[string][]string
	err error
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.txt[name]
	if !ok {
		return nil, customdomain.ErrDNSNotFound
	}
	return v, nil
}

func (e *env) dns() *fakeDNS {
	d := &fakeDNS{txt: map[string][]string{}}
	e.h.DNS = d
	return d
}

func TestDomainsCRUD(t *testing.T) {
	e := newEnv(t)
	tok := e.adminToken(t)
	rec, d := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "Acme.Example"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id, _ := d["id"].(string)
	if !strings.HasPrefix(id, "ord_") || len(id) != 26 || d["domain"] != "acme.example" || d["status"] != "pending" || d["org_id"] != e.orgA.ID ||
		d["verification_host"] != "_zeroauthy-org.acme.example" || d["verification_txt"] == "" || d["identity_provider_association"] != "unassociated" {
		t.Fatalf("created %v", d)
	}
	if rec, _ := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "acme.example"}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d", rec.Code)
	}
	if rec, b := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "bad_domain!"}); rec.Code != http.StatusBadRequest || b["validation_errors"] == nil {
		t.Fatalf("invalid = %d %v", rec.Code, b)
	}
	e.do(t, tok, "POST", "/domains", map[string]any{"domain": "two.example"})
	rec, list := e.do(t, tok, "GET", "/domains?take=1", nil)
	if items, _ := list["organization_domains"].([]any); rec.Code != 200 || len(items) != 1 || list["next"] == nil {
		t.Fatalf("page 1 = %d %v", rec.Code, list)
	}
	_, list2 := e.do(t, tok, "GET", "/domains?take=1&from="+list["next"].(string), nil)
	if items, _ := list2["organization_domains"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] == list["organization_domains"].([]any)[0].(map[string]any)["id"] {
		t.Fatalf("page 2 %v", list2)
	}
	if rec, g := e.do(t, tok, "GET", "/domains/"+id, nil); rec.Code != 200 || g["domain"] != "acme.example" {
		t.Fatalf("get = %d %v", rec.Code, g)
	}
	// Another organization's admin sees nothing.
	if rec, _ := e.do(t, e.tokenFor(t, e.carol.UserID, e.orgB.ID), "GET", "/domains/"+id, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("other org get = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "DELETE", "/domains/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "GET", "/domains/"+id, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete = %d", rec.Code)
	}
	// A new My Organization domain does not join organization discovery.
	_, d2 := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "disc.example"})
	got, err := e.st.OrganizationsII().GetDiscoveryDomain(context.Background(), e.tn.ID, e.orgA.ID, d2["id"].(string))
	must(t, err)
	if got.UseForOrganizationDiscovery {
		t.Fatal("discovery enabled by default")
	}
}

func TestDomainVerify(t *testing.T) {
	cases := []struct {
		name       string
		txt        func(want string) []string
		err        error
		otherOwner bool
		code       int
		status     string
	}{
		{"match", func(w string) []string { return []string{"unrelated", w} }, nil, false, http.StatusAccepted, "verified"},
		{"other value", func(string) []string { return []string{"someone-else"} }, nil, false, http.StatusAccepted, "failed"},
		{"no record", nil, nil, false, http.StatusAccepted, "failed"},
		{"resolver limit", nil, customdomain.ErrDNSLimit, false, http.StatusServiceUnavailable, "pending"},
		{"resolver timeout", nil, context.DeadlineExceeded, false, http.StatusServiceUnavailable, "pending"},
		{"verified elsewhere", func(w string) []string { return []string{w} }, nil, true, http.StatusAccepted, "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			dns := e.dns()
			tok := e.adminToken(t)
			_, d := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "acme.example"})
			if c.txt != nil {
				dns.txt["_zeroauthy-org.acme.example"] = c.txt(d["verification_txt"].(string))
			}
			dns.err = c.err
			if c.otherOwner {
				must(t, e.st.OrganizationsII().PutDiscoveryDomain(context.Background(), &store.OrganizationDiscoveryDomain{TenantID: e.tn.ID, OrganizationID: e.orgB.ID, ID: "dd_other", Domain: "acme.example", Status: "verified"}, true))
			}
			rec, v := e.do(t, tok, "POST", "/domains/"+d["id"].(string)+"/verify", nil)
			if rec.Code != c.code {
				t.Fatalf("verify = %d %s", rec.Code, rec.Body)
			}
			_, g := e.do(t, tok, "GET", "/domains/"+d["id"].(string), nil)
			if g["status"] != c.status {
				t.Fatalf("status %v, want %s", g["status"], c.status)
			}
			if c.code == http.StatusAccepted && v["status"] != c.status {
				t.Fatalf("verify body %v", v)
			}
			if strings.Contains(e.logs.String(), d["verification_txt"].(string)) {
				t.Fatal("verification value logged")
			}
		})
	}
	t.Run("no resolver", func(t *testing.T) {
		e := newEnv(t)
		tok := e.adminToken(t)
		_, d := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "acme.example"})
		if rec, _ := e.do(t, tok, "POST", "/domains/"+d["id"].(string)+"/verify", nil); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("verify without resolver = %d", rec.Code)
		}
	})
}

func TestDomainTakeover(t *testing.T) {
	e := newEnv(t)
	must(t, e.st.OrganizationsII().PutDiscoveryDomain(context.Background(), &store.OrganizationDiscoveryDomain{TenantID: e.tn.ID, OrganizationID: e.orgB.ID, ID: "dd_b", Domain: "acme.example", Status: "verified"}, true))
	if rec, b := e.do(t, e.adminToken(t), "POST", "/domains", map[string]any{"domain": "acme.example"}); rec.Code != http.StatusConflict {
		t.Fatalf("claim of a domain verified elsewhere = %d %v", rec.Code, b)
	}
	// A pending claim elsewhere does not block.
	must(t, e.st.OrganizationsII().DeleteDiscoveryDomain(context.Background(), e.tn.ID, e.orgB.ID, "dd_b"))
	must(t, e.st.OrganizationsII().PutDiscoveryDomain(context.Background(), &store.OrganizationDiscoveryDomain{TenantID: e.tn.ID, OrganizationID: e.orgB.ID, ID: "dd_b", Domain: "acme.example", Status: "pending"}, true))
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/domains", map[string]any{"domain": "acme.example"}); rec.Code != http.StatusCreated {
		t.Fatalf("claim beside a pending claim = %d", rec.Code)
	}
}

func TestDomainClaimExpiry(t *testing.T) {
	e := newEnv(t)
	dns := e.dns()
	tok := e.adminToken(t)
	_, stale := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "stale.example"})
	_, kept := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "kept.example"})
	dns.txt["_zeroauthy-org.kept.example"] = []string{kept["verification_txt"].(string)}
	e.do(t, tok, "POST", "/domains/"+kept["id"].(string)+"/verify", nil)
	e.now = e.now.Add(7*24*time.Hour + time.Second)
	tok = e.adminToken(t)
	if rec, _ := e.do(t, tok, "GET", "/domains/"+stale["id"].(string), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expired claim = %d", rec.Code)
	}
	_, list := e.do(t, tok, "GET", "/domains", nil)
	items, _ := list["organization_domains"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != kept["id"] {
		t.Fatalf("list %v", list)
	}
	if _, err := e.st.OrganizationsII().GetDiscoveryDomain(context.Background(), e.tn.ID, e.orgA.ID, stale["id"].(string)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired claim still stored: %v", err)
	}
}
