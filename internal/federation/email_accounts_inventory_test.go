package federation

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Documentation-only gate: no stores, provider calls or script execution.
func TestEmailAccountsInventory(t *testing.T) {
	b, err := os.ReadFile("email_accounts_inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Audiences  map[string]string
		Strategies map[string]struct {
			IsSocial bool `json:"is_social"`
			Scopes   []string
			Graph    bool
			Script   bool
			Options  map[string]struct {
				Type                                              string
				Default                                           json.RawMessage
				Immutable                                         *bool
				Secret, Disposition, Validation, Source, Evidence string
			}
		}
		Identities map[string]struct{ Subject, Identity, Public string }
		Deviations map[string]string
		Security   map[string]string
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inv.Audiences, map[string]string{"microsoft_personal": "windowslive", "microsoft_work_school": "waad", "google_accounts": "google-oauth2", "google_workspace": "google-oauth2"}) {
		t.Error("four audience contract")
	}
	for _, s := range []string{"windowslive", "waad", "google-oauth2"} {
		row, ok := inv.Strategies[s]
		if !ok {
			t.Errorf("missing %s", s)
			continue
		}
		if row.IsSocial != (s != "waad") || !reflect.DeepEqual(row.Scopes, []string{"openid", "profile", "email"}) || row.Graph || row.Script {
			t.Errorf("%s scope/classification/dependency", s)
		}
		for name, o := range row.Options {
			if o.Type == "" || len(o.Default) == 0 || o.Immutable == nil || o.Secret == "" || o.Disposition == "" || o.Validation == "" || o.Source == "" || o.Evidence == "" {
				t.Errorf("incomplete %s.%s", s, name)
			}
		}
		if row.Options["client_secret"].Secret != "write-only" {
			t.Errorf("%s secret", s)
		}
	}
	for strategy, fields := range map[string]map[string]string{
		"windowslive": {"strategy_version": "integer"},
		"waad":        {"identity_api": "string", "waad_protocol": "string", "userid_attribute": "string", "tenant_domain": "string", "useCommonEndpoint": "boolean"},
	} {
		for name, typ := range fields {
			if inv.Strategies[strategy].Options[name].Type != typ {
				t.Errorf("wire type %s.%s", strategy, name)
			}
		}
	}
	for _, strategy := range []string{"windowslive", "waad"} {
		for _, flag := range []string{"basic_profile", "ext_groups", "ext_profile", "ext_nested_groups", "ext_group_memberships", "api_enable_users", "api_enable_groups", "api_enable_contacts"} {
			row := inv.Strategies[strategy].Options[flag+"_false"]
			if row.Disposition != "inert" || string(row.Default) != "false" {
				t.Errorf("false-only flag %s.%s", strategy, flag)
			}
		}
	}
	for mode, want := range map[string][3]string{
		"personal":         {"<sub>", "<sub>", "windowslive|<sub>"},
		"single_directory": {"<oid>", "<connection>|<oid>", "waad|<connection>|<oid>"},
		"organizations":    {"<tid>:<oid>", "<connection>|<tid>:<oid>", "waad|<connection>|<tid>:<oid>"},
		"google":           {"<sub>", "<sub>", "google-oauth2|<sub>"},
	} {
		row := inv.Identities[mode]
		if row.Subject != want[0] || row.Identity != want[1] || row.Public != want[2] {
			t.Errorf("identity %s", mode)
		}
	}
	for _, key := range []string{"fixed_scopes", "no_graph", "email_verification", "organizations_only", "identity_encoding", "no_legacy_conversion", "public_cloud_only", "secret_post", "no_email_linking", "google_unchanged", "immutable_binding", "capability_preflight", "bounded_network", "strict_jwk_issuer", "no_assurance_translation", "token_projection", "metadata_only", "profile_sync", "no_refresh_guarantee"} {
		if inv.Deviations[key] == "" {
			t.Errorf("missing deviation %s", key)
		}
	}
	for _, s := range []string{"windowslive", "waad"} {
		for _, key := range []string{"discovery_url", "issuer", "authorizationURL", "tokenURL", "jwks_uri", "strategy_version_1", "offline_access", "freeform_scopes", "domain_aliases", "trust_email_verified", "email_verified", "userid_attribute_sub", "prompt", "claims", "acr_values", "max_age", "authParams", "authParamsMap", "upstream_params", "customHeaders", "fieldsMap", "scripts.fetchUserProfile", "use_wsfed_true", "graph_api", "ext_groups", "ext_profile", "ext_nested_groups", "ext_group_memberships", "api_enable_users", "api_enable_groups", "api_enable_contacts"} {
			if inv.Strategies[s].Options[key].Disposition != "rejected" {
				t.Errorf("missing rejection %s.%s", s, key)
			}
		}
	}
	for _, key := range []string{"issuer", "keys", "tenant", "claims", "endpoints", "cache", "ownership", "revision"} {
		if inv.Security[key] == "" {
			t.Errorf("missing security policy %s", key)
		}
	}
}
