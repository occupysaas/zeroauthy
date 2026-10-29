package orgrules

import (
	"slices"
	"strings"
	"testing"
)

type wantOp struct {
	scopes      []string
	match       string
	conditional []string
	status      int
	pagination  string
}

func TestOrganizationsInventory(t *testing.T) {
	want := map[string]wantOp{
		"GET /api/v2/organizations":                                             {[]string{"read:organizations"}, "all", nil, 200, "offset+checkpoint"},
		"POST /api/v2/organizations":                                            {[]string{"create:organizations"}, "all", []string{"create:organization_connections"}, 201, "none"},
		"GET /api/v2/organizations/{id}":                                        {[]string{"read:organizations"}, "all", nil, 200, "none"},
		"GET /api/v2/organizations/name/{name}":                                 {[]string{"read:organizations"}, "all", nil, 200, "none"},
		"PATCH /api/v2/organizations/{id}":                                      {[]string{"update:organizations"}, "all", nil, 200, "none"},
		"DELETE /api/v2/organizations/{id}":                                     {[]string{"delete:organizations"}, "all", nil, 204, "none"},
		"GET /api/v2/organizations/{id}/members":                                {[]string{"read:organization_members", "read:organization_member_roles"}, "any", []string{"read:organization_member_roles"}, 200, "offset+checkpoint"},
		"POST /api/v2/organizations/{id}/members":                               {[]string{"create:organization_members"}, "all", nil, 204, "none"},
		"DELETE /api/v2/organizations/{id}/members":                             {[]string{"delete:organization_members"}, "all", nil, 204, "none"},
		"GET /api/v2/organizations/{id}/members/{user_id}/roles":                {[]string{"read:organization_member_roles"}, "all", nil, 200, "offset"},
		"POST /api/v2/organizations/{id}/members/{user_id}/roles":               {[]string{"create:organization_member_roles"}, "all", nil, 204, "none"},
		"DELETE /api/v2/organizations/{id}/members/{user_id}/roles":             {[]string{"delete:organization_member_roles"}, "all", nil, 204, "none"},
		"GET /api/v2/organizations/{id}/members/{user_id}/effective-roles":      {[]string{"read:organization_member_effective_roles"}, "all", nil, 200, "checkpoint"},
		"GET /api/v2/organizations/{id}/roles/{role_id}/members":                {[]string{"read:organization_members", "read:roles"}, "all", nil, 200, "checkpoint"},
		"GET /api/v2/organizations/{id}/enabled_connections":                    {[]string{"read:organization_connections"}, "all", nil, 200, "offset"},
		"POST /api/v2/organizations/{id}/enabled_connections":                   {[]string{"create:organization_connections"}, "all", nil, 201, "none"},
		"GET /api/v2/organizations/{id}/enabled_connections/{connection_id}":    {[]string{"read:organization_connections"}, "all", nil, 200, "none"},
		"PATCH /api/v2/organizations/{id}/enabled_connections/{connection_id}":  {[]string{"update:organization_connections"}, "all", nil, 200, "none"},
		"DELETE /api/v2/organizations/{id}/enabled_connections/{connection_id}": {[]string{"delete:organization_connections"}, "all", nil, 204, "none"},
		"GET /api/v2/users/{id}/organizations":                                  {[]string{"read:users", "read:organizations"}, "any", nil, 200, "offset+checkpoint"},
	}
	ops := Inventory()
	if len(ops) != len(want) {
		t.Fatalf("operations=%d, want %d", len(ops), len(want))
	}
	for _, op := range ops {
		key := op.Method + " " + op.Path
		w, ok := want[key]
		if !ok {
			t.Fatalf("unexpected or duplicate operation %s", key)
		}
		delete(want, key)
		if !slices.Equal(op.RequiredScopes, w.scopes) || op.ScopeMatch != w.match {
			t.Errorf("%s scopes=%v/%s want %v/%s", key, op.RequiredScopes, op.ScopeMatch, w.scopes, w.match)
		}
		if !slices.Equal(op.ConditionalScopes, w.conditional) {
			t.Errorf("%s conditional scopes=%v want %v", key, op.ConditionalScopes, w.conditional)
		}
		if op.SuccessStatus != w.status || op.Pagination != w.pagination {
			t.Errorf("%s status/pagination=%d/%s want %d/%s", key, op.SuccessStatus, op.Pagination, w.status, w.pagination)
		}
		if !strings.HasPrefix(op.SourceURL, "https://auth0.com/docs/api/management/v2/") || op.RequestShape == "" || op.ResponseShape == "" || len(op.ErrorStatuses) == 0 {
			t.Errorf("%s incomplete contract", key)
		}
		if op.Evidence != "documented" && op.Evidence != "observed" {
			t.Errorf("%s evidence=%q", key, op.Evidence)
		}
		if op.Lifecycle != "GA" && op.Lifecycle != "EA" {
			t.Errorf("%s lifecycle=%q", key, op.Lifecycle)
		}
		if strings.Contains(op.Path, "/connections") && !strings.Contains(op.Path, "/enabled_connections") {
			t.Errorf("%s: /connections is deferred, not a Plan 29 operation", key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing operations %v", want)
	}

	m := InventoryMetadata()

	fields := map[string]FieldContract{}
	for _, f := range m.Fields {
		fields[f.Object+"."+f.Name] = f
		if f.Evidence == "" || (f.SourceURL == "" && f.Decision == "") {
			t.Errorf("field %s.%s has no provenance", f.Object, f.Name)
		}
	}
	for key, w := range map[string]struct {
		values []string
		def    string
	}{
		"client.organization_usage":                                  {[]string{"deny", "allow", "require"}, "deny"},
		"client.organization_require_behavior":                       {[]string{"no_prompt", "pre_login_prompt", "post_login_prompt"}, "no_prompt"},
		"client.organization_discovery_methods":                      {[]string{"email", "organization_name"}, ""},
		"tenant.flags.allow_organization_name_in_authentication_api": {[]string{"true", "false"}, "false"},
	} {
		f, ok := fields[key]
		if !ok {
			t.Errorf("missing field %s", key)
			continue
		}
		if !slices.Equal(f.Values, w.values) || f.Default != w.def {
			t.Errorf("field %s values=%v default=%q", key, f.Values, f.Default)
		}
	}

	deferred := map[string]string{
		"invitations":                      "30",
		"invitation_parameter":             "30",
		"user_invitation_email":            "30",
		"organization_client_grants":       "30",
		"client_grant_organization_fields": "30",
		"discovery_domains":                "30",
		"email_organization_discovery":     "30",
		"client_credentials_organization":  "30",
		"organization_clients_ea":          "30",
		"organizations_search":             "30",
		"organization_groups":              "38",
		"token_quota":                      "35",
		"is_app_entitlement_active":        "30",
		"organization_connections_ea":      "30",
		"my_organization_api":              "42",
		"saml_wsfed_organization_login":    "37",
		"change_password_organization":     "30",
	}
	seen := map[string]bool{}
	for _, d := range Deferred() {
		if seen[d.Name] {
			t.Errorf("duplicate deferred %s", d.Name)
		}
		seen[d.Name] = true
		if d.Plan == "" || d.Source == "" {
			t.Errorf("deferred %s missing plan or source", d.Name)
		}
		if plan, ok := deferred[d.Name]; ok {
			if d.Plan != plan {
				t.Errorf("deferred %s plan=%s want %s", d.Name, d.Plan, plan)
			}
			delete(deferred, d.Name)
		}
	}
	if len(deferred) != 0 {
		t.Errorf("missing deferred items %v", deferred)
	}

	limits := map[string]LimitContract{}
	for _, l := range m.Limits {
		limits[l.Name] = l
		if !strings.HasPrefix(l.Source, "https://") && l.Source != "D-0055" && l.Source != ObservationSource {
			t.Errorf("limit %s has no source or decision: %q", l.Name, l.Source)
		}
	}
	for name, value := range map[string]int{
		"name_chars_max": 50, "display_name_chars_max": 255,
		"metadata_keys_max": 25, "metadata_key_chars_max": 50, "metadata_value_chars_max": 255,
		"enabled_connections_create_max": 10, "enabled_connections_per_organization_max": 50,
		"organizations_per_tenant_max": 10000, "roles_per_member_max": 50, "batch_ids_max": 10,
		"page_max": 1000, "per_page_max": 100, "per_page_default": 50, "take_max": 100, "take_default": 50,
		"picker_organizations_max": 20, "organization_id_random_chars": 16,
	} {
		l, ok := limits[name]
		if !ok || l.Value != value {
			t.Errorf("limit %s=%+v want %d", name, l, value)
		}
	}
	for _, name := range []string{"enabled_connections_per_organization_max", "organizations_per_tenant_max", "roles_per_member_max", "batch_ids_max"} {
		if limits[name].Source != "D-0055" {
			t.Errorf("limit %s must be a D-0055 local decision", name)
		}
	}

	status := map[int]string{
		1: "partly_observed", 2: "partly_observed", 3: "unavailable", 4: "unavailable", 5: "unavailable",
		6: "observed", 7: "observed", 8: "observed", 9: "partly_observed", 10: "unavailable",
	}
	for _, d := range m.Decisions {
		w, ok := status[d.Item]
		if !ok {
			t.Fatalf("unexpected or duplicate D-0055 item %d", d.Item)
		}
		delete(status, d.Item)
		if d.Status != w {
			t.Errorf("item %d status=%q want %q", d.Item, d.Status, w)
		}
		if d.Topic == "" || d.Value == "" || d.Decision != "D-0055" {
			t.Errorf("item %d incomplete", d.Item)
		}
		switch d.Status {
		case "observed":
			if d.Evidence != "observed" || d.Source != ObservationSource {
				t.Errorf("item %d observed without observation source", d.Item)
			}
		case "partly_observed":
			if d.Evidence != "observed" || d.Source != ObservationSource || d.LocalDefault == "" {
				t.Errorf("item %d partly observed needs observation source and local remainder", d.Item)
			}
		case "unavailable":
			if d.Evidence != "local" || d.LocalDefault == "" {
				t.Errorf("item %d unavailable must keep a local default", d.Item)
			}
		}
	}
	if len(status) != 0 {
		t.Errorf("missing D-0055 items %v", status)
	}

	rules := map[string]bool{}
	for _, r := range m.Rules {
		rules[r.Name] = true
		if r.Value == "" || (r.SourceURL == "" && r.Decision == "") {
			t.Errorf("rule %s has no value or provenance", r.Name)
		}
		switch r.Evidence {
		case "documented", "observed":
		case "local-decision":
			if r.Decision != "D-0055" {
				t.Errorf("rule %s local without D-0055", r.Name)
			}
		default:
			t.Errorf("rule %s evidence=%q", r.Name, r.Evidence)
		}
	}
	for _, name := range []string{
		"name_format", "organization_id_format", "display_name_default", "metadata_values", "metadata_keys",
		"branding_rules", "patch_replace", "patch_empty_body", "get_omits_enabled_connections",
		"response_constant_fields", "delete_not_idempotent", "malformed_id", "list_default_order",
		"members_fields", "members_unknown_user", "member_roles_non_member", "member_roles_unknown_role",
		"member_role_retention", "effective_roles_shape", "role_members_shape", "connection_flags",
		"enabled_connection_delete", "require_grant_conflict", "pre_login_prompt_usage",
		"post_login_prompt_oidc", "discovery_methods_rule", "authorize_errors", "empty_organization_param",
		"connection_not_enabled", "client_credentials_organization", "connections_alias_ruling",
		"member_order", "picker", "par_binding",
	} {
		if !rules[name] {
			t.Errorf("missing rule %s", name)
		}
	}

	tools := map[string]bool{}
	for _, tool := range m.Tools {
		tools[tool.Name] = true
		if tool.Version == "" || tool.Repo == "" || len(tool.Files) == 0 || tool.Exposes == "" {
			t.Errorf("tool %s incomplete provenance", tool.Name)
		}
	}
	for _, name := range []string{"auth0-cli", "node-auth0", "auth0-deploy-cli"} {
		if !tools[name] {
			t.Errorf("missing tool provenance %s", name)
		}
	}
}

func TestOrganizationsInventoryReturnsIndependentValues(t *testing.T) {
	ops := Inventory()
	ops[0].RequiredScopes[0] = "changed"
	if Inventory()[0].RequiredScopes[0] == "changed" {
		t.Fatal("caller mutation changed inventory")
	}
	d := Deferred()
	d[0].Plan = "changed"
	if Deferred()[0].Plan == "changed" {
		t.Fatal("caller mutation changed deferred list")
	}
}
