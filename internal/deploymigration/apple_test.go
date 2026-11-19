package deploymigration

import (
	"bytes"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"strings"
	"testing"
	"time"
)

func TestAppleFederationImportCredentialSelection(t *testing.T) {
	export := Export{Resources: map[string]json.RawMessage{"connections": json.RawMessage(`[{"name":"apple","strategy":"apple","options":{"client_id":"test.acme.web","team_id":"ABCDE12345","kid":"ABCDE67890"}}]`)}}
	raw, err := FederationImport(export, map[string]string{"apple": "private-key-sentinel"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Options map[string]any }
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Options["app_secret"] != "private-key-sentinel" || rows[0].Options["client_secret"] != nil {
		t.Fatal("wrong credential option")
	}
	for _, field := range []string{"client_secret", "app_secret"} {
		export.Resources["connections"] = json.RawMessage(`[{"name":"apple","strategy":"apple","options":{"` + field + `":"exported-sentinel"}}]`)
		if _, err := FederationImport(export, map[string]string{"apple": "private-key-sentinel"}); err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("exported credential accepted or leaked")
		}
	}
}

func TestAppleBootstrapPreservesNativeClientFields(t *testing.T) {
	bootstrap, err := seed.Parse([]byte("tenants:\n - name: destination\n   domains: [dest.example.test]\n"))
	if err != nil {
		t.Fatal(err)
	}
	source := Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"native-id","name":"Native Apple","app_type":"native","token_endpoint_auth_method":"none","grant_types":["authorization_code"],"native_social_login":{"apple":{"enabled":true},"facebook":{"enabled":false}},"mobile":{"ios":{"team_id":"ABCDE12345","app_bundle_identifier":"test.acme.app"},"android":{"app_package_name":"test.acme.android"}}}]`)}}
	prepared, err := PrepareBootstrap(source, bootstrap, nil, BootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	result, err := ApplyBootstrap(t.Context(), st, prepared, w, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	client, err := st.Clients().Get(t.Context(), result.TenantID, "native-id")
	if err != nil {
		t.Fatal(err)
	}
	if !client.NativeSocialLogin["apple"] || client.NativeSocialLogin["facebook"] || client.Mobile.IOS.TeamID != "ABCDE12345" || client.Mobile.Android.AppPackageName != "test.acme.android" {
		t.Fatal("bootstrap lost native settings")
	}
}

func TestEnterpriseFederationImportSecretPolicy(t *testing.T) {
	for _, tc := range []struct {
		strategy, options string
		secret            bool
	}{{"oidc", `{"type":"front_channel","client_id":"client"}`, false}, {"oidc", `{"type":"back_channel","token_endpoint_auth_method":"private_key_jwt","client_id":"client"}`, false}, {"okta", `{"domain":"dev-1.okta.com","client_id":"client"}`, true}} {
		raw := json.RawMessage(`[{"name":"enterprise","strategy":"` + tc.strategy + `","options":` + tc.options + `}]`)
		credentials := map[string]string{}
		if tc.secret {
			credentials["enterprise"] = "fixture-secret"
		}
		prepared, e := FederationImport(Export{Resources: map[string]json.RawMessage{"connections": raw}}, credentials)
		if e != nil {
			t.Fatal(e)
		}
		var rows []map[string]any
		if e := json.Unmarshal(prepared, &rows); e != nil {
			t.Fatal(e)
		}
		_, has := rows[0]["options"].(map[string]any)["client_secret"]
		if has != tc.secret {
			t.Fatal("incorrect secret injection")
		}
	}
}
