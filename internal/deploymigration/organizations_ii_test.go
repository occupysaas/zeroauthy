package deploymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrganizationsIIDeployRoundTrip(t *testing.T) {
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			for _, body := range []string{
				`[{"name":"example","token_quota":{"client_credentials":{"per_day":100}}}]`,
				`[{"name":"example","connections":[{"name":"Db","organization_member_access_level":"full"}]}]`,
				`[{"name":"example","discovery_domains":[{"domain":"example.test","status":"verified"}]}]`,
				`[{"name":"example","invitations":[{"invitation_url":"secret"}]}]`,
				`[{"name":"example","unknown_active_policy":true}]`,
				`[{"name":"example","clients":[{"client_id":"Browser","client_secret":"secret"}]}]`,
				`[{"name":"example","client_grants":[{"client_id":"Browser","audience":"unsupported"}]}]`,
			} {
				dir := t.TempDir()
				p := filepath.Join(dir, "tenant.yaml")
				content := "organizations: " + body
				if format == "directory" {
					os.Mkdir(filepath.Join(dir, "organizations"), 0700)
					p = filepath.Join(dir, "organizations", "example.json")
					content = strings.TrimSuffix(strings.TrimPrefix(body, "["), "]")
				}
				if e := os.WriteFile(p, []byte(content), 0600); e != nil {
					t.Fatal(e)
				}
				if format == "directory" {
					p = dir
				}
				if _, e := LoadExport(p, format); e == nil {
					t.Fatalf("unsupported policy accepted: %s", body)
				}
			}
		})
	}
}

func TestOrganizationsIIDeployRoundTripRejectsActiveGrantPolicy(t *testing.T) {
	for _, raw := range []string{`[{"organization_usage":"require"}]`, `[{"organization_usage":"allow"}]`, `[{"allow_any_organization":true}]`} {
		if e := ValidateOrganizations(Export{Resources: map[string]json.RawMessage{"clientGrants": json.RawMessage(raw)}}); e == nil {
			t.Fatalf("active grant policy accepted: %s", raw)
		}
	}
}

func TestOrganizationsIIDeployRoundTripRejectsAmbiguousGrantReference(t *testing.T) {
	source := Export{Resources: map[string]json.RawMessage{
		"organizations": json.RawMessage(`[{"name":"example","client_grants":[{"client_id":"Service"}]}]`),
		"clients":       json.RawMessage(`[{"client_id":"service-id","name":"Service"}]`),
		"clientGrants":  json.RawMessage(`[{"id":"one","client_id":"Service","audience":"https://one.test"},{"id":"two","client_id":"Service","audience":"https://two.test"}]`),
	}}
	if e := ValidateOrganizations(source); e == nil {
		t.Fatal("ambiguous application-only grant mapping accepted")
	}
	source.Resources["clientGrants"] = json.RawMessage(`[]`)
	if e := ValidateOrganizations(source); e == nil {
		t.Fatal("unresolved grant mapping accepted")
	}
}
