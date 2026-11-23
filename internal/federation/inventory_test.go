package federation

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// This contract gate catches missing/contradictory field and projection decisions
// before later rules, adapters and Management handlers consume this inventory.
// It exercises no store, network, provider, tenant or script runtime.
func TestFederationInventory(t *testing.T) {
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Strategies map[string]struct {
			IsSocial      bool     `json:"is_social"`
			IDFormat      string   `json:"id_format"`
			DefaultScopes []string `json:"default_scopes"`
			Options       map[string]struct {
				Type, Validation, Secret, Runtime, Source string
				Default                                   json.RawMessage
			}
		}
		Operations []struct {
			ID, Method, Path, Response, Source string
			Scopes                             []string
			Status                             int
			Pagination                         struct {
				SelectBy                             []string `json:"select_by"`
				CheckpointWins                       bool     `json:"checkpoint_wins"`
				ResponseFields                       []string `json:"response_fields"`
				FirstPage, Continuation, Termination string
				IncludeTotals                        string   `json:"include_totals"`
				OmittedFields                        []string `json:"omitted_fields"`
				DefaultTake                          int      `json:"default_take"`
				MaxTake                              int      `json:"max_take"`
			} `json:"pagination"`
		}
		Patch    struct{ Options, Secret, Immutable []string }
		Identity struct {
			SubjectDelimiters, Parsing, Collision, Imported string
			MaxSubjectBytes                                 int `json:"max_subject_bytes"`
		}
		Tokens struct {
			Operations, Scopes, Fields, Excluded []string
			CacheControl                         string `json:"cache_control"`
			MissingRefresh                       string `json:"missing_refresh"`
		}
		Script struct {
			Signature                    string
			Context, Requests, Forbidden []string
			RootFields                   []string `json:"root_fields"`
			ExtraClaims                  string   `json:"extra_claims"`
		}
		Unsupported             map[string]struct{ Disposition, Reason, Source string }
		UpstreamParameterPolicy struct {
			RejectedKeys                []string `json:"rejected_keys"`
			AllValuesRejected           bool     `json:"all_values_rejected"`
			RejectAliasesToRejectedKeys bool     `json:"reject_aliases_to_rejected_keys"`
		} `json:"upstream_parameter_policy"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	t.Run("assurance_parameters_rejected_before_inert_storage", func(t *testing.T) {
		for _, key := range []string{"acr_values", "max_age", "claims", "prompt"} {
			if !slices.Contains(inv.UpstreamParameterPolicy.RejectedKeys, key) {
				t.Errorf("assurance parameter %s can be stored inert instead of rejected", key)
			}
		}
		if !inv.UpstreamParameterPolicy.AllValuesRejected {
			t.Error("reserved parameter rejection must apply to every value, including prompt=login/max_age=0")
		}
		if !inv.UpstreamParameterPolicy.RejectAliasesToRejectedKeys {
			t.Error("aliases to rejected assurance parameters must also be rejected")
		}
	})
	if len(inv.Strategies) != 8 {
		t.Fatalf("need exactly eight strategies, got %d", len(inv.Strategies))
	}
	for strategy, want := range map[string]string{
		"google-oauth2": "google-oauth2|<sub>", "oauth2": "oauth2|<connection-name>|<subject>", "oidc": "oidc|<connection-name>|<sub>",
		"apple": "apple|<sub>", "github": "github|<id>", "okta": "okta|<connection-name>|<sub>",
	} {
		row, ok := inv.Strategies[strategy]
		if !ok || row.IDFormat != want || row.IsSocial != (strategy != "oidc" && strategy != "okta") {
			t.Errorf("strategy %s: missing ID/social decision", strategy)
		}
		for field, rule := range row.Options {
			if rule.Type == "" || rule.Validation == "" || rule.Secret == "" || rule.Runtime == "" || rule.Source == "" || len(rule.Default) == 0 {
				t.Errorf("incomplete %s option %s", strategy, field)
			}
			if !slices.Contains([]string{"active", "stored-only", "rejected"}, rule.Runtime) {
				t.Errorf("unclassified runtime %s.%s", strategy, field)
			}
		}
		credential := "client_secret"
		if strategy == "apple" {
			credential = "app_secret"
		}
		for _, field := range []string{"client_id", credential, "set_user_root_attributes"} {
			if _, ok := row.Options[field]; !ok {
				t.Errorf("%s missing %s", strategy, field)
			}
		}
		if row.Options[credential].Secret != "write-only" {
			t.Errorf("%s exposes credentials", strategy)
		}
	}
	apple := inv.Strategies["apple"]
	if !slices.Equal(apple.DefaultScopes, []string{"name", "email"}) {
		t.Error("Apple default scopes must request first-login name and email")
	}
	for _, field := range []string{"team_id", "kid", "scope", "freeform_scopes", "name", "email", "upstream_params", "non_persistent_attrs"} {
		if _, ok := apple.Options[field]; !ok {
			t.Errorf("Apple missing %s", field)
		}
	}
	if apple.Options["scope"].Type != "string" {
		t.Error("Apple scope must use the documented space-separated string")
	}
	google := inv.Strategies["google-oauth2"]
	if !slices.Equal(google.DefaultScopes, []string{"openid", "profile", "email"}) {
		t.Fatal("Google default scopes")
	}
	for _, flag := range []string{"email", "profile"} {
		row := google.Options[flag]
		if row.Type != "boolean" || row.Runtime != "active" || string(row.Default) != "true" {
			t.Errorf("unsupported Google flag %s", flag)
		}
	}
	oidc := inv.Strategies["oidc"]
	if oidc.Options["type"].Validation != "front_channel or back_channel; omitted means front_channel" || string(oidc.Options["type"].Default) != `"front_channel"` {
		t.Fatal("OIDC channel contract")
	}
	if oidc.Options["scopes"].Type != "string" || !strings.Contains(oidc.Options["scopes"].Validation, "openid") {
		t.Fatal("OIDC scopes wire format/openid requirement")
	}
	for _, field := range []string{"authorizationURL", "tokenURL", "scope", "scripts.fetchUserProfile"} {
		if inv.Strategies["oauth2"].Options[field].Runtime != "active" {
			t.Errorf("OAuth2 missing active %s", field)
		}
	}
	operations := map[string]bool{}
	for _, op := range inv.Operations {
		if op.ID == "" || operations[op.ID] || op.Method == "" || !strings.HasPrefix(op.Path, "/api/v2/") || op.Response == "" || op.Source == "" || len(op.Scopes) == 0 || op.Status < 200 || op.Status >= 300 {
			t.Errorf("incomplete operation %+v", op)
		}
		operations[op.ID] = true
	}
	t.Run("connection_list_checkpoint_contract", func(t *testing.T) {
		for _, op := range inv.Operations {
			if op.ID != "ListConnections" {
				continue
			}
			p := op.Pagination
			if !slices.Equal(p.SelectBy, []string{"take", "from"}) || !p.CheckpointWins {
				t.Error("take/from presence must select checkpoint ahead of offset parameters")
			}
			if !slices.Equal(p.ResponseFields, []string{"connections", "next?"}) || !strings.Contains(op.Response, "{connections:[...],next?}") {
				t.Error("connection-list checkpoint response must carry connections and optional next")
			}
			if p.FirstPage != "omit from; supply take" || p.Continuation != "send previous next unchanged as from" || p.Termination != "next absent on terminal or empty page; never empty-string next" {
				t.Error("checkpoint first/continuation/termination semantics missing")
			}
			if p.IncludeTotals != "ignored in checkpoint mode, including when true" || !slices.Equal(p.OmittedFields, []string{"start", "limit", "length", "total"}) {
				t.Error("checkpoint must omit offset summary fields regardless of include_totals")
			}
			if p.DefaultTake != 50 || p.MaxTake != 100 {
				t.Error("checkpoint take must default to 50 and be bounded at 100")
			}
		}
	})
	for _, id := range []string{"ListConnections", "CreateConnection", "GetConnection", "UpdateConnection", "DeleteConnection", "GetConnectionClients", "UpdateConnectionClients", "GetUser", "ListUsers", "ListUsersByEmail", "LinkIdentity", "UnlinkIdentity", "ExportUsers"} {
		if !operations[id] {
			t.Errorf("missing operation %s", id)
		}
	}
	if !slices.Contains(inv.Patch.Options, "replace") || !slices.Contains(inv.Patch.Secret, "omitted preserves") || !slices.Contains(inv.Patch.Secret, "empty/null rejected") {
		t.Fatal("PATCH replacement/credential semantics missing")
	}
	for _, field := range []string{"strategy", "name", "client_id", "discovery_url", "authorizationURL", "tokenURL", "scripts.fetchUserProfile"} {
		if !slices.Contains(inv.Patch.Immutable, field) {
			t.Errorf("missing immutable %s", field)
		}
	}
	if inv.Identity.SubjectDelimiters != "allowed in subject" || inv.Identity.Parsing != "split provider and connection prefixes only; remaining bytes are the subject" || inv.Identity.MaxSubjectBytes != 1024 || inv.Identity.Collision != "fail closed with conflict; never merge by public ID or email" || inv.Identity.Imported == "" {
		t.Fatal("ambiguous ID or import/collision policy")
	}
	if !slices.Equal(inv.Tokens.Operations, []string{"GetUser"}) || !slices.Equal(inv.Tokens.Scopes, []string{"read:users", "read:user_idp_tokens"}) || !slices.Equal(inv.Tokens.Fields, []string{"identities[].access_token", "identities[].refresh_token"}) || inv.Tokens.CacheControl != "no-store" || inv.Tokens.MissingRefresh != "preserve previous" {
		t.Fatal("token projection/scope/refresh contract")
	}
	for _, excluded := range []string{"ListUsers", "ListUsersByEmail", "LinkIdentity", "UnlinkIdentity", "ExportUsers", "jobs", "userinfo", "local tokens", "console"} {
		if !slices.Contains(inv.Tokens.Excluded, excluded) {
			t.Errorf("token leak surface not excluded: %s", excluded)
		}
	}
	if inv.Script.Signature != "function fetchUserProfile(accessToken, context, callback)" || !slices.Equal(inv.Script.Context, []string{"access_token", "refresh_token", "token_type", "scope", "expires_in", "id_token"}) || !slices.Contains(inv.Script.Requests, "request.get(options, callback)") || !slices.Contains(inv.Script.RootFields, "user_id") || inv.Script.ExtraClaims != "ignored; user_metadata only from explicit bounded object" {
		t.Fatal("profile-script API/mapping contract")
	}
	for _, forbidden := range []string{"app_metadata", "blocked", "identities", "password", "local authorization claims"} {
		if !slices.Contains(inv.Script.Forbidden, forbidden) {
			t.Errorf("script privilege missing: %s", forbidden)
		}
	}
	for _, option := range []string{"dpop_signing_alg", "upstream_params", "authParams", "authParamsMap", "customHeaders", "fieldsMap", "freeform_scopes", "domain_restriction", "pkce_disabled", "development_keys", "connected_accounts", "direct_network", "arbitrary_npm", "issuer_metadata", "token_vault"} {
		row, ok := inv.Unsupported[option]
		if !ok || !slices.Contains([]string{"stored-only", "rejected", "unavailable"}, row.Disposition) || row.Reason == "" || row.Source == "" {
			t.Errorf("missing unsupported disposition %s", option)
		}
	}
}

// TestFederationInventoryGitHub freezes the Plan 39c GitHub contract: the
// flag-to-scope table, the pinned API version, the rate-limit signals and the
// extra profile fields. Sources are public GitHub documentation read on
// 2026-11-18; Auth0 documents none of the email, scope or user ID semantics.
func TestFederationInventoryGitHub(t *testing.T) {
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Strategies map[string]struct {
			IsSocial bool                       `json:"is_social"`
			IDFormat string                     `json:"id_format"`
			Options  map[string]json.RawMessage `json:"options"`
		}
		ProviderProtocol struct {
			GitHub struct {
				ScopeFlags       map[string]string                        `json:"scope_flags"`
				APIVersion       string                                   `json:"api_version"`
				RateLimitSignals []struct{ Status, Header, Value string } `json:"rate_limit_signals"`
			} `json:"github"`
		} `json:"provider_protocol"`
		GitHubProfile struct {
			ProviderData []string `json:"provider_data"`
		} `json:"github_profile"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	row, ok := inv.Strategies["github"]
	if !ok || !row.IsSocial || row.IDFormat != "github|<id>" {
		t.Fatal("github strategy missing or not social with github|<id>")
	}
	want := map[string]string{
		"admin_org": "admin:org", "admin_public_key": "admin:public_key", "admin_repo_hook": "admin:repo_hook",
		"delete_repo": "delete_repo", "follow": "user:follow", "gist": "gist", "notifications": "notifications",
		"public_repo": "public_repo", "read_org": "read:org", "read_public_key": "read:public_key",
		"read_repo_hook": "read:repo_hook", "read_user": "read:user", "repo": "repo", "repo_deployment": "repo_deployment",
		"repo_status": "repo:status", "write_org": "write:org", "write_public_key": "write:public_key",
		"write_repo_hook": "write:repo_hook", "email": "user:email", "profile": "",
	}
	got := inv.ProviderProtocol.GitHub.ScopeFlags
	if len(got) != 20 {
		t.Errorf("scope_flags has %d entries, want 20", len(got))
	}
	for flag, scope := range want {
		g, ok := got[flag]
		if !ok || g != scope {
			t.Errorf("scope flag %s = %q (present %v), want %q", flag, g, ok, scope)
		}
		if _, ok := row.Options[flag]; !ok {
			t.Errorf("github option %s missing", flag)
		}
	}
	for _, field := range []string{"client_id", "client_secret", "set_user_root_attributes", "scope", "freeform_scopes", "upstream_params"} {
		if _, ok := row.Options[field]; !ok {
			t.Errorf("github option %s missing", field)
		}
	}
	if inv.ProviderProtocol.GitHub.APIVersion == "" {
		t.Error("api_version must be pinned")
	}
	if len(inv.ProviderProtocol.GitHub.RateLimitSignals) == 0 {
		t.Error("rate_limit_signals missing")
	}
	wantData := []string{"login", "html_url", "blog", "company", "location", "bio", "public_repos", "followers", "following", "created_at", "updated_at"}
	if !slices.Equal(inv.GitHubProfile.ProviderData, wantData) {
		t.Errorf("provider_data = %v, want %v", inv.GitHubProfile.ProviderData, wantData)
	}
}

// TestFederationInventorySAML: the samlp block classifies every option, and
// SP private keys in options are rejected (Plan 37a).
func TestFederationInventorySAML(t *testing.T) {
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Strategies map[string]struct {
			IsSocial bool   `json:"is_social"`
			IDFormat string `json:"id_format"`
			Options  map[string]struct{ Type, Validation, Secret, Runtime, Source string }
		}
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	row, ok := inv.Strategies["samlp"]
	if !ok || row.IsSocial || row.IDFormat == "" {
		t.Fatal("samlp strategy missing or social")
	}
	for _, field := range []string{"signInEndpoint", "signingCert", "thumbprints", "fieldsMap", "idpinitiated", "signing_key", "decryptionKey", "domain_aliases"} {
		r, ok := row.Options[field]
		if !ok || r.Type == "" || r.Validation == "" || r.Runtime == "" || r.Source == "" {
			t.Errorf("samlp option %s incomplete", field)
		}
	}
	for _, k := range []string{"signing_key", "decryptionKey"} {
		if row.Options[k].Runtime != "rejected" || row.Options[k].Secret != "write-only" {
			t.Errorf("%s must be rejected and write-only", k)
		}
	}
}

// TestFederationInventoryADFS: the adfs block classifies every
// ConnectionOptionsADFS option (Plan 37b).
func TestFederationInventoryADFS(t *testing.T) {
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Strategies map[string]struct {
			IsSocial bool   `json:"is_social"`
			IDFormat string `json:"id_format"`
			Options  map[string]struct{ Type, Validation, Secret, Runtime, Source string }
		}
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	row, ok := inv.Strategies["adfs"]
	if !ok || row.IsSocial || row.IDFormat == "" {
		t.Fatal("adfs strategy missing or social")
	}
	for _, field := range []string{"adfs_server", "fedMetadataXml", "signInEndpoint", "thumbprints", "prev_thumbprints", "thumbprints_sha384", "entityId",
		"user_id_attribute", "should_trust_email_verified_connection", "domain_aliases", "set_user_root_attributes", "icon_url", "non_persistent_attrs",
		"upstream_params", "tenant_domain"} {
		r, ok := row.Options[field]
		if !ok || r.Type == "" || r.Validation == "" || r.Runtime == "" || r.Source == "" || r.Secret != "public" {
			t.Errorf("adfs option %s incomplete", field)
		}
	}
}
