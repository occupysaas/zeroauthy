package main

import (
	"encoding/json"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestOrganizationsIIDeployRoundTrip(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "organizations", Status: "included"}}}
	makeExport := func(body string) deploymigration.Export {
		return deploymigration.Export{Resources: map[string]json.RawMessage{"organizations": json.RawMessage(body)}}
	}
	source := makeExport(`[{"id":"old","name":"example","is_app_entitlement_active":true,"third_party_client_access":"allow","metadata":{"department":"engineering"},"connections":[{"name":"Db","is_enabled":false},{"name":"Other","is_enabled":true}],"clients":[{"client_id":"Browser","use_for_member_access":true},{"client_id":"Other","use_for_member_access":false}],"discovery_domains":[{"domain":"example.test","status":"pending","use_for_organization_discovery":true},{"domain":"other.test","status":"pending","use_for_organization_discovery":false}]}]`)
	target := makeExport(`[{"id":"new","name":"example","is_app_entitlement_active":true,"third_party_client_access":"allow","metadata":{"department":"engineering"},"connections":[{"name":"Other","is_enabled":true},{"name":"Db","is_enabled":false}],"clients":[{"client_id":"Other","use_for_member_access":false},{"client_id":"Browser","use_for_member_access":true}],"discovery_domains":[{"domain":"other.test","status":"pending","use_for_organization_discovery":false},{"domain":"example.test","status":"pending","use_for_organization_discovery":true}]}]`)
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("policy not equivalent: %+v", r.Differences)
	}
	var rows []map[string]any
	json.Unmarshal(target.Resources["organizations"], &rows)
	rows[0]["is_app_entitlement_active"] = false
	b, _ := json.Marshal(rows)
	target.Resources["organizations"] = b
	if r := Compare(source, target, m, Domains{}); r.Equivalent {
		t.Fatal("lost entitlement not detected")
	}
}
