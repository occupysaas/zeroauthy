package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// TestE2EPrivateEmailProviderCredentialAfterImport is invoked only by the
// isolated deploy CLI lane. It checks the private local database state without
// adding a credential-recovery API or putting fixture credentials in seeds.
func TestE2EPrivateEmailProviderCredentialAfterImport(t *testing.T) {
	dsn, expected, master := os.Getenv("ZEROAUTHY_STORAGE__DSN"), os.Getenv("E2E_EMAIL_PRIVATE_SECRET"), os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY")
	if dsn == "" || expected == "" || master == "" {
		t.Skip("only runs from the isolated Plan 21 deploy lane")
	}
	key, err := base64.StdEncoding.DecodeString(master)
	if err != nil {
		t.Fatal("invalid test master key")
	}
	wrapper, err := keys.NewLocalWrapper(key)
	if err != nil {
		t.Fatal("cannot load test wrapper")
	}
	st, err := sqlstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal("cannot open isolated test database")
	}
	defer st.Close()
	tenant, err := st.Tenants().GetByName(context.Background(), "e2ecli-target")
	if err != nil {
		t.Fatal("target tenant is missing")
	}
	provider, err := st.EmailProviders().Get(context.Background(), tenant.ID)
	if err != nil {
		t.Fatal("target provider is missing")
	}
	plain, err := keys.OpenEmailProvider(wrapper, tenant.ID, provider.Name, provider.SealedCredentials)
	if err != nil {
		t.Fatal("target credentials did not decrypt")
	}
	var credentials map[string]any
	if json.Unmarshal(plain, &credentials) != nil {
		t.Fatal("target provider credential payload is invalid")
	}
	actual, ok := credentials["api_key"].(string)
	if !ok || actual != expected {
		t.Fatalf("private target credential changed during deployment import (provider=%s, public config keys=%v, credential keys=%v, present=%t, actual length=%d, expected length=%d)", provider.Name, mapKeys(provider.PublicConfig), mapKeys(credentials), ok, len(actual), len(expected))
	}
}

func mapKeys(m map[string]any) []string { out:=make([]string,0,len(m)); for key:=range m { out=append(out,key) }; return out }
