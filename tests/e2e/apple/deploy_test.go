package apple

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// Private assertions run only inside the isolated actual-CLI matrix. No key
// recovery endpoint is added to the public API.
func TestDeployedAppleKey(t *testing.T) {
	if os.Getenv("E2E_M39A_DEPLOY_WORK") == "" {
		t.Skip("requires isolated Apple deploy CLI lane")
	}
	expected, err := os.ReadFile(filepath.Join(os.Getenv("E2E_M39A_DEPLOY_WORK"), "apple.p8"))
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	master, err := base64.StdEncoding.DecodeString(os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY"))
	if err != nil {
		t.Fatal("invalid fixture wrapper")
	}
	wrapper, err := keys.NewLocalWrapper(master)
	if err != nil {
		t.Fatal("fixture wrapper unavailable")
	}
	for _, side := range []struct{ env, tenant string }{{"E2E_M39A_SOURCE_DSN", "apple-source"}, {"E2E_M39A_TARGET_DSN", "apple-target"}} {
		st, err := sqlstore.Open(t.Context(), os.Getenv(side.env))
		if err != nil {
			t.Fatal("fixture database unavailable")
		}
		defer st.Close()
		tenant, err := st.Tenants().GetByName(t.Context(), side.tenant)
		if err != nil {
			t.Fatal("fixture tenant unavailable")
		}
		c, err := st.Connections().GetByName(t.Context(), tenant.ID, "Apple-deploy")
		if err != nil {
			t.Fatal("imported connection missing")
		}
		secret, err := federation.OpenCredentials(wrapper, tenant.ID, c.ID, c.FederationSecretsSealed)
		if err != nil || secret.ClientSecret != string(expected) {
			t.Fatal("signing key was not preserved by private reinjection")
		}
		public, _ := json.Marshal(c.Extra)
		if bytes.Contains(public, expected) || bytes.Contains(c.FederationSecretsSealed, expected) || c.Extra["app_secret"] != nil || c.Extra["client_secret"] != nil {
			t.Fatal("plaintext key persisted")
		}
	}
}
