package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestPhoneHandlers(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Resources {
		// D-0059: the pinned CLI exporter reads provider.data, which its SDK
		// never returns; provider wire coverage is asserted directly instead.
		if r.Name == "guardianFactorProviders" && (r.Status != "tool-unsupported" || !strings.Contains(r.Reason, "provider.data")) {
			t.Errorf("guardianFactorProviders must be tool-unsupported citing the provider.data CLI bug, got %q", r.Status)
		}
	}
	for _, name := range []string{"guardianFactorTemplates", "guardianPhoneFactorSelectedProvider", "guardianPhoneFactorMessageTypes", "guardianPhoneFactorSettings", "attackProtection"} {
		found := false
		for _, r := range m.Resources {
			if r.Name == name {
				found = true
				if r.Status != "included" || r.Fixture == nil {
					t.Errorf("%s must be included with a fixture", name)
				}
			}
		}
		if !found {
			t.Errorf("missing %s", name)
		}
	}
}

// TestPinnedPhoneHandlers is a focused Management boundary test, separate from
// the four-cell Deploy CLI acceptance lane. The installed versions are checked
// by the script; no tool methods, response shapes or statuses are adapted.
func TestPinnedPhoneHandlers(t *testing.T) {
	modules := os.Getenv("ZA_DEPLOY_CLI_MODULES")
	if modules == "" {
		modules = "../node_modules"
	}
	modules, err := filepath.Abs(modules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(modules, "auth0-deploy-cli/package.json")); err != nil {
		if os.Getenv("ZA_REQUIRE_DEPLOY_CLI") == "1" {
			t.Fatal(err)
		}
		t.Skip("pinned Deploy CLI unavailable; install tests/e2e dependencies")
	}
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "fixture", Name: "fixture"}
	if err = st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	wrapper, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h := &mgmt.Handlers{Store: st, Wrapper: wrapper, Log: slog.Default()}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: r.Host}))
		path := strings.TrimPrefix(r.URL.Path, "/api/v2")
		if strings.HasPrefix(path, "/attack-protection/") {
			feature := strings.TrimPrefix(path, "/attack-protection/")
			if feature == "phone-provider-protection" {
				if r.Method == "GET" {
					h.GetPhoneProviderProtection(w, r)
				} else {
					h.UpdatePhoneProviderProtection(w, r)
				}
			} else if r.Method == "GET" {
				h.GetProtection(w, r, feature)
			} else {
				h.UpdateProtection(w, r, feature)
			}
			return
		}
		for _, route := range mfarules.Inventory().Routes {
			if route.Path == path && route.Method == r.Method {
				h.MFAOperation(w, r, route.Operation, "", "")
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "phone-pinned-roundtrip.cjs", strings.TrimPrefix(srv.URL, "https://"))
	cmd.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+cert, "ZA_DEPLOY_CLI_MODULES="+modules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pinned handlers: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestComparePhoneProviderProtection(t *testing.T) {
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "attackProtection", Status: "included"})
	source, target := comparisonFixture(), comparisonFixture()
	source.Resources["attackProtection"] = json.RawMessage(`{"phoneProviderProtection":{"type":"exponential"}}`)
	target.Resources["attackProtection"] = json.RawMessage(`{"phoneProviderProtection":{"type":"exponential"}}`)
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("equal phone protection differs: %+v", r.Differences)
	}
	target.Resources["attackProtection"] = json.RawMessage(`{"phoneProviderProtection":{"type":"default"}}`)
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("phone protection policy change was ignored")
	}
}
