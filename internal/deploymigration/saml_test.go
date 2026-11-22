package deploymigration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// samlp connections carry no provider secret: FederationImport needs none
// and refuses one (Plan 37a).
func TestFederationImportSAML(t *testing.T) {
	export := Export{Resources: map[string]json.RawMessage{"connections": json.RawMessage(`[{"name":"corp-saml","strategy":"samlp","options":{"signInEndpoint":"https://idp.example/sso"}}]`)}}
	out, err := FederationImport(export, nil)
	if err != nil {
		t.Fatalf("samlp import: %v", err)
	}
	if strings.Contains(string(out), "client_secret") {
		t.Fatal("a secret was injected into a samlp connection")
	}
	if _, err := FederationImport(export, map[string]string{"corp-saml": "unexpected"}); err == nil {
		t.Fatal("a provider secret was accepted for samlp")
	}
}

func TestBootstrapSAMLAddon(t *testing.T) {
	f, err := seed.Parse([]byte(`tenants: [{name: destination, domains: [dest.example.test]}]`))
	if err != nil {
		t.Fatal(err)
	}
	source := Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"sp","name":"SP","app_type":"spa","token_endpoint_auth_method":"none","callbacks":["https://sp.example/acs"],"addons":{"samlp":{"audience":"urn:sp"}}}]`)}}
	prepared, err := PrepareBootstrap(source, f, nil, BootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	defer st.Close()
	w, _ := keys.NewLocalWrapper([]byte(strings.Repeat("t", 32)))
	result, err := ApplyBootstrap(t.Context(), st, prepared, w, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.Clients().Get(t.Context(), result.TenantID, "sp")
	if err != nil || c.Addons == nil || c.Addons.SAMLP == nil || c.Addons.SAMLP.Audience != "urn:sp" {
		t.Fatalf("bootstrap dropped the add-on: %+v %v", c, err)
	}
}
