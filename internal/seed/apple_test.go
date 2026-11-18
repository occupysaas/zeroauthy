package seed

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const appleSeed = `
tenants:
 - name: acme
   domains: [acme.test]
   clients:
    - client_id: native
      app_type: native
      token_endpoint_auth_method: none
      native_social_login: {apple: {enabled: true}, facebook: {enabled: false}}
      mobile: {ios: {team_id: ABCDE12345, app_bundle_identifier: test.acme.app}}
   connections:
    - name: apple
      strategy: apple
      enabled_clients: [native]
      options:
       client_id: test.acme.web
       team_id: ABCDE12345
       kid: ABCDE67890
       app_secret: REFERENCE
`

func appleSeedKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestAppleSeedReferencesAndOwnership(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	secret := appleSeedKey(t)
	t.Setenv("ZA_APPLE_SEED_KEY", secret)
	doc := strings.Replace(appleSeed, "REFERENCE", "env://ZA_APPLE_SEED_KEY", 1)
	apply := func() {
		t.Helper()
		f, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, st, f, fixedNow, w); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, _ := st.Connections().GetByName(ctx, tn.ID, "apple")
	creds, err := federation.OpenCredentials(w, tn.ID, c.ID, c.FederationSecretsSealed)
	if err != nil || creds.ClientSecret != secret || c.Extra["app_secret"] != nil {
		t.Fatal("Apple key not sealed")
	}
	cl, err := st.Clients().Get(ctx, tn.ID, "native")
	if err != nil {
		t.Fatal(err)
	}
	if !cl.NativeSocialLogin["apple"] || cl.NativeSocialLogin["facebook"] || cl.Mobile.IOS.AppBundleIdentifier != "test.acme.app" {
		t.Fatal("native client fields lost")
	}
	apply()
	same, _ := st.Connections().GetByName(ctx, tn.ID, "apple")
	if same.ID != c.ID || same.FederationRevision != c.FederationRevision {
		t.Fatal("unchanged seed rotated key or ownership")
	}
	t.Setenv("ZA_APPLE_SEED_KEY", appleSeedKey(t))
	apply()
	rotated, _ := st.Connections().GetByName(ctx, tn.ID, "apple")
	if rotated.ID != c.ID || rotated.FederationRevision != c.FederationRevision+1 {
		t.Fatal("rotation lost ownership")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "apple.p8"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seed.yaml"), []byte(strings.Replace(appleSeed, "REFERENCE", "file://apple.p8", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "seed.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(strings.Replace(appleSeed, "REFERENCE", "file://"+filepath.Join(dir, "apple.p8"), 1))); err != nil {
		t.Fatal(err)
	}
}

func TestAppleSeedRejectsUnsafeReferencesAndInvalidClientFields(t *testing.T) {
	t.Setenv("ZA_APPLE_SEED_BAD", "secret-sentinel")
	for _, ref := range []string{"inline-secret-sentinel", "env://ZA_APPLE_SEED_MISSING", "env://ZA_APPLE_SEED_BAD", "file:///missing-secret-sentinel", "file://relative.p8"} {
		_, err := Parse([]byte(strings.Replace(appleSeed, "REFERENCE", ref, 1)))
		if err == nil {
			t.Fatalf("accepted reference %q", ref)
		}
		if strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), ref) {
			t.Fatal("secret reference leaked in error")
		}
	}
	t.Setenv("ZA_APPLE_SEED_KEY", appleSeedKey(t))
	for _, fields := range []string{"{apple: {enabled: yesplease}}", "{apple: {enabled: true, extra: true}}", "{other: {enabled: true}}", "null"} {
		doc := strings.Replace(strings.Replace(appleSeed, "REFERENCE", "env://ZA_APPLE_SEED_KEY", 1), "{apple: {enabled: true}, facebook: {enabled: false}}", fields, 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("accepted native fields %s", fields)
		}
	}
}
