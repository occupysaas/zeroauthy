package logrules

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Removing a published code, route, secret annotation or pagination bound must
// fail this contract test before another task can silently change the wire API.
func TestLogsInventory(t *testing.T) {
	data, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatalf("frozen logs inventory missing: %v", err)
	}
	var inv struct {
		Marker     string         `json:"marker"`
		IDPattern  string         `json:"id_pattern"`
		Limits     map[string]int `json:"limits"`
		Categories []string       `json:"categories"`
		Codes      []struct {
			Type, Description, Category, Source string
			StatsKind                           string `json:"stats_kind"`
			Emitted                             bool
			Status                              string
			Plan                                int
			Triggers                            []struct{ File, Function string }
		} `json:"codes"`
		Routes []struct {
			Method, Path, Source, Envelope string
			ScopeMatch                     string `json:"scope_match"`
			Scopes                         []string
			Parameters                     []struct{ Name, Type, In, Rule string }
			Errors                         map[string]string
		} `json:"routes"`
		Sinks []struct {
			Type, Source, Delivery string
			Fields                 []struct {
				Name, Type       string
				Secret, Required bool
			}
		} `json:"sinks"`
		Fields     []struct{ Name, Column, Type, Source string } `json:"fields"`
		Allowlists map[string][]string                           `json:"allowlists"`
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Marker != "[REDACTED]" || inv.IDPattern != "^[0-9]{56}$" {
		t.Errorf("marker/ID contract: %q %q", inv.Marker, inv.IDPattern)
	}
	for name, want := range map[string]int{"per_page_max": 100, "take_max": 100, "page_results_max": 1000, "id_digits": 56, "stats_default_days": 7, "stats_max_days": 366} {
		if inv.Limits[name] != want {
			t.Errorf("%s=%d want %d", name, inv.Limits[name], want)
		}
	}
	cats := map[string]bool{}
	for _, c := range strings.Fields("auth.login.fail auth.login.notification auth.login.success auth.logout.fail auth.logout.success auth.signup.fail auth.signup.success auth.silent_auth.fail auth.silent_auth.success auth.token_exchange.fail auth.token_exchange.success management.fail management.success scim.event system.notification user.fail user.notification user.success actions other") {
		cats[c] = true
	}
	if len(inv.Categories) != len(cats) {
		t.Errorf("categories=%d want %d", len(inv.Categories), len(cats))
	}
	seenCategories := map[string]bool{}
	for _, c := range inv.Categories {
		if !cats[c] || seenCategories[c] {
			t.Errorf("invalid/duplicate category %s", c)
		}
		seenCategories[c] = true
	}
	expectedCodes := strings.Fields("actions_execution_failed f fcoa fens fp fu organization_access_denied scv w s scoa sdel sens federated_logout_failed flo oidc_backchannel_logout_failed universal_logout_failed oidc_backchannel_logout_succeeded slo universal_logout_succeeded fs ss fdelsa fsa sdelsa ssa ciba_exchange_failed failed_on_behalf_of_token_exchange fdeleacft feacft feccft fecte fede feoobft feotpft fepft fepotpft fercft ferrt fertft idjag_exchange_failed jwt_bearer_exchange_failed ciba_exchange_succeeded feta idjag_exchange_succeeded sdeleacft seacft seccft secte sede seoobft seotpft sepft sepkoobft sepkotpft sepkrcft sercft sertft seta success_on_behalf_of_token_exchange gd_email_settings_update gd_phone_settings_update mgmt_api_read sapi acls_summary ciba_start_failed ciba_start_succeeded cls fco fdeac fi flows_execution_completed flows_execution_failed forms_submission_failed forms_submission_succeeded fpar fpurh gd_auth_email_verification gd_auth_failed gd_auth_rejected gd_auth_succeed gd_otp_rate_limit_exceed gd_recovery_failed gd_recovery_succeed gd_send_email gd_send_email_verification gd_send_pn gd_send_pn_failure gd_send_sms gd_send_sms_failure gd_send_voice gd_send_voice_failure gd_start_auth gd_start_enroll_failed gd_tenant_update gd_webauthn_challenge_failed gd_webauthn_enrollment_failed kms_key_management_failure kms_key_management_success kms_key_state_changed limit_sul mfar organization_member_added passkey_challenge_failed passkey_challenge_started pla pwd_leak reset_pwd_leak resource_cleanup rich_consents_access_error si signup_pwd_leak wn wum fscim sscim acul_sdk_notice api_limit api_limit_warning appi custom_domain_verification_failed depnote directory_sync_completed directory_sync_failed directory_sync_started fcpro fui limit_delegation limit_mu limit_phone limit_signup_otp limit_wc connected_accounts_connection_failed connected_accounts_delete_failed fce fcp fcph fcpn fcpr fcu fd fdeaz fdecc fdu fn fv fvr my_account_authentication_method_failed ss_sso_failure cs gd_enrollment_complete gd_start_enroll gd_unenroll gd_update_device_account ss_sso_info ublkdu connected_accounts_connection_succeeded connected_accounts_delete_succeeded my_account_authentication_method_succeeded sce scp scpn scpr scu sd sdu srrt ss_sso_success sui sv svr fc coff con admin_update_launch sys_os_update_start sys_os_update_end sys_update_start sys_update_end fapi")
	gotCodes := map[string]bool{}
	for _, c := range inv.Codes {
		if gotCodes[c.Type] {
			t.Errorf("duplicate code %s", c.Type)
		}
		gotCodes[c.Type] = true
		switch c.StatsKind {
		case "", "logins", "signups", "leaked_passwords":
		default:
			t.Errorf("unknown stats kind %s", c.StatsKind)
		}
		if c.StatsKind != "" && !c.Emitted {
			t.Errorf("deferred %s contributes stats", c.Type)
		}
		if c.Description == "" || !cats[c.Category] || !strings.HasPrefix(c.Source, "https://auth0.com/docs/") {
			t.Errorf("incomplete code %s", c.Type)
		}
		if !c.Emitted && c.Plan == 0 && c.Status != "not_planned" {
			t.Errorf("deferred code %s lacks plan", c.Type)
		}
		if c.Emitted {
			if len(c.Triggers) == 0 {
				t.Errorf("emitted code %s lacks trigger", c.Type)
			}
			for _, tr := range c.Triggers {
				body, err := os.ReadFile("../../" + tr.File)
				if err != nil || tr.Function == "" || !strings.Contains(string(body), "func "+tr.Function+"(") && !strings.Contains(string(body), ") "+tr.Function+"(") {
					t.Errorf("%s trigger %s:%s missing", c.Type, tr.File, tr.Function)
				}
			}
		}
	}
	if len(gotCodes) != len(expectedCodes) {
		t.Errorf("codes=%d want %d", len(gotCodes), len(expectedCodes))
	}
	for _, c := range expectedCodes {
		if !gotCodes[c] {
			t.Errorf("missing published code %s", c)
		}
	}
	wantRoutes := map[string]string{
		"GET /api/v2/logs": "read:logs", "GET /api/v2/logs/{id}": "read:logs", "GET /api/v2/users/{id}/logs": "read:logs read:logs_users",
		"GET /api/v2/log-streams": "read:log_streams", "POST /api/v2/log-streams": "create:log_streams",
		"GET /api/v2/log-streams/{id}": "read:log_streams", "PATCH /api/v2/log-streams/{id}": "update:log_streams", "DELETE /api/v2/log-streams/{id}": "delete:log_streams",
		"GET /api/v2/stats/daily": "read:stats", "GET /api/v2/stats/active-users": "read:stats",
	}
	for _, r := range inv.Routes {
		key := r.Method + " " + r.Path
		scope, ok := wantRoutes[key]
		if !ok {
			t.Errorf("unexpected/duplicate %s", key)
		}
		delete(wantRoutes, key)
		if strings.Join(r.Scopes, " ") != scope || r.ScopeMatch != "all" || r.Envelope == "" || !strings.HasPrefix(r.Source, "https://auth0.com/docs/") {
			t.Errorf("incomplete route %s", key)
		}
		for _, status := range []string{"401", "403", "429", "501"} {
			if r.Errors[status] == "" {
				t.Errorf("%s missing error %s", key, status)
			}
		}
		for _, p := range r.Parameters {
			if p.Name == "" || p.Type == "" || p.In == "" || p.Rule == "" {
				t.Errorf("%s incomplete parameter", key)
			}
		}
	}
	if len(wantRoutes) > 0 {
		t.Errorf("missing routes %v", wantRoutes)
	}
	secrets := map[string][]string{"http": {"httpAuthorization", "httpCustomHeaders"}, "datadog": {"datadogApiKey"}, "splunk": {"splunkToken"}, "sumo": {"sumoSourceAddress"}, "segment": {"segmentWriteKey"}, "mixpanel": {"mixpanelServiceAccountPassword"}, "eventbridge": {}, "eventgrid": {}}
	for _, s := range inv.Sinks {
		want, ok := secrets[s.Type]
		if !ok {
			t.Errorf("unexpected/duplicate sink %s", s.Type)
		}
		delete(secrets, s.Type)
		if s.Source == "" || s.Delivery == "" || len(s.Fields) == 0 {
			t.Errorf("incomplete sink %s", s.Type)
		}
		seen := map[string]bool{}
		for _, f := range s.Fields {
			if f.Name == "" || f.Type == "" {
				t.Errorf("incomplete sink field %s", s.Type)
			}
			seen[f.Name] = f.Secret
		}
		for _, name := range want {
			if !seen[name] {
				t.Errorf("sink %s secret %s unmarked", s.Type, name)
			}
		}
	}
	if len(secrets) > 0 {
		t.Errorf("missing sinks %v", secrets)
	}
	fields := map[string]bool{}
	for _, f := range inv.Fields {
		fields[f.Name] = true
		if f.Column == "" || f.Type == "" || f.Source == "" {
			t.Errorf("incomplete searchable field %s", f.Name)
		}
	}
	for _, name := range strings.Fields("client_id client_name connection connection_id description date hostname ip log_id organization_id user_id user_name user_agent strategy strategy_type type") {
		if !fields[name] {
			t.Errorf("missing searchable field %s", name)
		}
	}
	for _, resource := range strings.Fields("clients users connections resource-servers client-grants organizations actions email-templates emails tickets jobs tenants log-streams default") {
		if _, ok := inv.Allowlists[resource]; !ok {
			t.Errorf("missing body allowlist %s", resource)
		}
	}
}

func TestRulesSnapshots(t *testing.T) {
	codes := Codes()
	if len(codes) != 180 {
		t.Fatalf("codes=%d", len(codes))
	}
	i := 0
	for len(codes[i].Triggers) == 0 {
		i++
	}
	codes[i].Description = "changed"
	codes[i].Triggers[0].Function = "changed"
	if Codes()[i].Description == "changed" || Codes()[i].Triggers[0].Function == "changed" {
		t.Fatal("Codes exposes shared state")
	}
	fields := Fields()
	fields[0].Column = "changed"
	if Fields()[0].Column == "changed" {
		t.Fatal("Fields exposes shared state")
	}
	sink, ok := SinkSchema("http")
	if !ok {
		t.Fatal("http missing")
	}
	sink.Fields[0].Name = "changed"
	again, _ := SinkSchema("http")
	if again.Fields[0].Name == "changed" {
		t.Fatal("SinkSchema exposes shared state")
	}
	if _, ok := SinkSchema("unknown"); ok {
		t.Fatal("unknown sink accepted")
	}
	inv := Inventory()
	inv.Limits["take_max"] = 1
	if Inventory().Limits["take_max"] != 100 {
		t.Fatal("Inventory exposes shared state")
	}
	allow := BodyAllowlist("clients")
	allow[0] = "changed"
	if BodyAllowlist("clients")[0] == "changed" || len(BodyAllowlist("unknown")) != 0 {
		t.Fatal("unsafe allowlist boundary")
	}
	if Marker != "[REDACTED]" {
		t.Fatal("marker drift")
	}
}

func TestLogsOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Inventory().Routes {
		path := doc.Paths.Value(r.Path)
		if path == nil {
			t.Errorf("missing path %s", r.Path)
			continue
		}
		op := path.GetOperation(r.Method)
		if op == nil {
			t.Errorf("missing operation %s %s", r.Method, r.Path)
			continue
		}
		if op.Security == nil {
			t.Errorf("%s missing scoped security", r.Path)
			continue
		}
		found := false
		for _, req := range *op.Security {
			if slices.Equal(req["managementToken"], r.Scopes) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s scope mismatch", r.Path)
		}
		for _, p := range r.Parameters {
			var actual *openapi3.Parameter
			for _, ref := range op.Parameters {
				if ref.Value.Name == p.Name {
					actual = ref.Value
				}
			}
			if actual == nil {
				t.Errorf("%s missing parameter %s", r.Path, p.Name)
				continue
			}
			if p.Name == "per_page" || p.Name == "take" {
				if actual.Schema.Value.Max == nil || *actual.Schema.Value.Max != 100 {
					t.Errorf("%s %s max drift", r.Path, p.Name)
				}
			}
		}
		if op.Responses.Value(strconv.Itoa(r.SuccessStatus)) == nil {
			t.Errorf("%s success status drift", r.Path)
		}
		for status := range r.Errors {
			if op.Responses.Value(status) == nil {
				t.Errorf("%s missing error %s", r.Path, status)
			}
		}
	}
}

func TestDailyStatsOpenAPIFormat(t *testing.T) {
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Components.Schemas["LogDailyStat"].Value.Properties["date"].Value.Format; got != "date-time" {
		t.Fatalf("daily date format=%q, want RFC3339 date-time", got)
	}
}

func TestLogObjectFieldTypes(t *testing.T) {
	inv := Inventory()
	fields := map[string]string{}
	for _, f := range inv.LogFields {
		fields[f.Name] = f.Type
	}
	if fields["$event_schema"] != "object" {
		t.Errorf("$event_schema type=%s, want object", fields["$event_schema"])
	}
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["LogEvent"].Value
	for name, typ := range fields {
		actual := schema.Properties[name]
		if actual == nil || !actual.Value.Type.Is(typ) {
			t.Errorf("LogEvent.%s type must be %s", name, typ)
		}
	}
}

func TestRedactedStreamResponseSchema(t *testing.T) {
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"id": "lst_test", "type": "http", "status": "active", "sink": map[string]any{"httpEndpoint": "https://example.test/logs", "httpAuthorization": Marker, "httpCustomHeaders": Marker}}
	if err := doc.Components.Schemas["LogStreamHTTP"].Value.VisitJSON(value); err != nil {
		t.Fatalf("read schema rejects redacted credentials: %v", err)
	}
}

// Page-mode field projection may remove even the otherwise required event
// identity fields. Both bare arrays and totals envelopes must describe it.
func TestLogProjectionResponseSchemas(t *testing.T) {
	data, err := os.ReadFile("../../api/management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	list := doc.Paths.Value("/api/v2/logs").Get.Responses.Value("200").Value.Content["application/json"].Schema.Value
	full := doc.Paths.Value("/api/v2/logs/{id}").Get.Responses.Value("200").Value.Content["application/json"].Schema.Value
	fullEvent := map[string]any{"log_id": strings.Repeat("0", 55) + "1", "date": "2026-10-30T12:00:00Z", "type": "s"}
	if err := full.VisitJSON(fullEvent); err != nil {
		t.Fatalf("GET-by-ID rejects a full event: %v", err)
	}
	for _, name := range []string{"log_id", "date", "type"} {
		if !slices.Contains(full.Required, name) {
			t.Errorf("GET-by-ID no longer requires %s", name)
		}
	}
	for _, tc := range []struct {
		name string
		item map[string]any
	}{
		{"include_user_id", map[string]any{"user_id": "auth0|example"}},
		{"exclude_log_id_and_type", map[string]any{"date": "2026-10-30T12:00:00Z", "user_id": "auth0|example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []any{tc.item}
			if err := list.VisitJSON(items); err != nil {
				t.Errorf("bare array rejects projected event: %v", err)
			}
			totals := map[string]any{"logs": items, "start": float64(0), "limit": float64(50), "length": float64(1), "total": float64(1)}
			if err := list.VisitJSON(totals); err != nil {
				t.Errorf("totals envelope rejects projected event: %v", err)
			}
			if err := full.VisitJSON(tc.item); err == nil {
				t.Error("GET-by-ID accepted an incomplete event")
			}
		})
	}
}
