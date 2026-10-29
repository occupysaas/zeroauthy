package orgrules

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOrganizationsIIContractAudit(t *testing.T) {
	// Requiring explicit local-vs-public evidence prevents a guessed scope or
	// default from silently becoming a parity assertion.
	var inv struct {
		Operations []map[string]any `json:"organizations_ii_operations"`
	}
	if err := json.Unmarshal(inventoryJSON, &inv); err != nil {
		t.Fatal(err)
	}
	for _, op := range inv.Operations {
		for _, field := range []string{"scope_evidence", "null_omission", "error_mapping"} {
			if op[field] == nil || op[field] == "" {
				t.Errorf("%s %s missing %s", op["method"], op["path"], field)
			}
		}
	}
	for _, name := range []string{"management", "authentication"} {
		data, err := os.ReadFile("../../api/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := openapi3.NewLoader().LoadFromData(data)
		if err != nil {
			t.Fatal(err)
		}
		if name == "management" {
			for _, op := range OrganizationsIIInventory() {
				if !strings.HasPrefix(op.Path, "/api/v2/") {
					continue
				}
				item := doc.Paths.Value(op.Path)
				if item == nil || item.GetOperation(op.Method) == nil {
					t.Errorf("missing YAML %s %s", op.Method, op.Path)
				}
			}
			for _, name := range []string{"OrganizationInvitationCreate", "OrganizationInvitation", "OrganizationClientAssociation", "OrganizationDiscoveryDomain"} {
				if doc.Components.Schemas[name] == nil {
					t.Errorf("missing schema %s", name)
				}
			}
		} else {
			if doc.Components.Schemas["ChangePasswordRequest"].Value.Properties["organization"] == nil {
				t.Error("password change organization parameter missing")
			}
			for _, p := range doc.Paths.Value("/authorize").Get.Parameters {
				if p.Value.Name == "invitation" && strings.Contains(p.Value.Description, "not available") {
					t.Error("invitation remains deferred in authorize contract")
				}
			}
		}
	}
}

func TestOrganizationsIIDocumentedShapes(t *testing.T) {
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	create := doc.Components.Schemas["OrganizationInvitationCreate"].Value
	ttl := create.Properties["ttl_sec"].Value
	if ttl.Default != float64(604800) || ttl.Max == nil || *ttl.Max != 2592000 {
		t.Errorf("invitation TTL contract: %+v", ttl)
	}
	clients := doc.Components.Schemas["IICreateOrganizationClientRequestItem"].Value
	if !hasString(clients.Required, "use_for_member_access") {
		t.Error("client association flag must be required")
	}
	invites := doc.Components.Schemas["IIListOrganizationInvitationsOffsetPaginatedResponseContent"].Value
	if invites.Properties["total"] != nil {
		t.Error("invitation envelope must omit total")
	}
	domains := doc.Components.Schemas["IIListOrganizationDiscoveryDomainsResponseContent"].Value
	if domains.Properties["domains"] == nil || domains.Properties["discovery_domains"] != nil {
		t.Error("domain collection key must be domains")
	}
	search := doc.Paths.Value("/api/v2/organizations/search").Get
	for _, p := range search.Parameters {
		s := p.Value.Schema.Value
		if p.Value.Name == "q" && (s.MaxLength == nil || *s.MaxLength != 1000) {
			t.Error("search q limit")
		}
		if p.Value.Name == "take" && (s.Max == nil || *s.Max != 100 || s.Default != float64(50)) {
			t.Error("search take bounds/default")
		}
	}
}
func hasString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestOrganizationsIIScopesAndLocalRulings(t *testing.T) {
	want := map[string]string{
		"GET /api/v2/organizations/search":                     "read:organizations,read:organizations_summary",
		"GET /api/v2/client-grants/{id}/organizations":         "read:organization_client_grants",
		"POST /api/v2/organizations/{id}/clients":              "create:organization_clients",
		"PATCH /api/v2/organizations/{id}/clients/{client_id}": "update:organization_clients",
		"DELETE /api/v2/organizations/{id}/clients":            "delete:organization_clients",
		"POST /api/v2/organizations/{id}/discovery-domains":    "create:organization_discovery_domains",
		"POST /api/v2/tickets/password-change":                 "create:user_tickets",
	}
	for _, op := range OrganizationsIIInventory() {
		key := op.Method + " " + op.Path
		if expected, ok := want[key]; ok {
			if strings.Join(op.RequiredScopes, ",") != expected {
				t.Errorf("%s scopes=%v want %s", key, op.RequiredScopes, expected)
			}
			delete(want, key)
		}
		if strings.Contains(op.Path, "/connections") && !strings.Contains(op.NullOmission, "member access=limited") {
			t.Errorf("%s loses D-0055 member default", key)
		}
		if op.Path == "/api/v2/organizations/search" {
			limits := strings.Join(op.Limits, " ")
			for _, v := range []string{"q_max=1000", "predicates_max=5", "take_default=50", "take_max=100", "depth_max=16"} {
				if !strings.Contains(limits, v) {
					t.Errorf("missing %s", v)
				}
			}
		}
		if op.ScopeEvidence == "" || op.NullOmission == "" || len(op.ErrorMapping) == 0 {
			t.Errorf("%s loses typed audit fields", key)
		}
	}
	for k := range want {
		t.Errorf("missing scoped route %s", k)
	}
}
