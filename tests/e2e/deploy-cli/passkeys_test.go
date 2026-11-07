package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TestManifestPasskeyHandlers keeps the pinned handler classification and its
// fixtures in step with the passkey fields each handler carries.
func TestManifestPasskeyHandlers(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]ManifestResource{}
	for _, r := range m.Resources {
		entries[r.Name] = r
	}
	for name, mention := range map[string]string{
		"clients":         "mobile",
		"customDomains":   "relying_party_identifier",
		"guardianFactors": "WebAuthn",
		"databases":       "passkey_options",
		"connections":     "databases handler",
	} {
		e, ok := entries[name]
		if !ok {
			t.Errorf("missing handler %s", name)
			continue
		}
		if !strings.Contains(e.Reason, mention) {
			t.Errorf("%s reason does not mention %q: %s", name, mention, e.Reason)
		}
	}
	for name, field := range map[string]string{
		"clients":         `"urn:okta:params:oauth:grant-type:webauthn"`,
		"customDomains":   `"relying_party_identifier"`,
		"guardianFactors": `"webauthn-roaming"`,
	} {
		e := entries[name]
		if e.Status != "included" || e.Fixture == nil {
			t.Errorf("%s must stay included with a fixture", name)
			continue
		}
		b, err := os.ReadFile(*e.Fixture)
		if err != nil || !bytes.Contains(b, []byte(field)) {
			t.Errorf("%s fixture lacks %s (%v)", name, field, err)
		}
	}
	if b, err := os.ReadFile(*entries["clients"].Fixture); err != nil || !bytes.Contains(b, []byte(`"mobile"`)) {
		t.Errorf("clients fixture lacks mobile (%v)", err)
	}
	found := false
	for _, s := range m.NoHandler {
		if s.Setting == "guardian.webauthn_roaming.user_verification" {
			found = true
			if !strings.Contains(s.Reason, "LR33b-22") || s.Owner == "" {
				t.Errorf("user verification entry lacks owner or LR33b-22: %+v", s)
			}
		}
	}
	if !found {
		t.Error("security-key user verification is not recorded as having no Auth0 handler")
	}
	bad := m
	bad.NoHandler = append(append([]NoHandlerSetting{}, m.NoHandler...), NoHandlerSetting{Setting: "clients", Owner: "Plan 33b", Reason: "x"})
	names := make([]string, 0, len(m.Resources))
	for _, r := range m.Resources {
		names = append(names, r.Name)
	}
	if ValidateManifest(bad, names) == nil {
		t.Error("a registered handler was recorded as having no handler")
	}
	bad.NoHandler = []NoHandlerSetting{{Setting: "x.y"}}
	if ValidateManifest(bad, names) == nil {
		t.Error("no-handler entry without owner and reason accepted")
	}
}

// TestComparePasskeyFields: the migration comparator treats every passkey
// field as significant.
func TestComparePasskeyFields(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "clients", Status: "included"}, {Name: "customDomains", Status: "included"}, {Name: "guardianFactors", Status: "included"}}}
	const clients = `[{"client_id":"%s","name":"Native","app_type":"native","grant_types":["authorization_code","urn:okta:params:oauth:grant-type:webauthn"],"mobile":{"ios":{"team_id":"ABCDE12345","app_bundle_identifier":"com.example.app"},"android":{"app_package_name":"com.example.app","sha256_cert_fingerprints":["AA:BB"]}}}]`
	makeExport := func(id, domainRP, roaming string) deploymigration.Export {
		return deploymigration.Export{Resources: map[string]json.RawMessage{
			"clients":         json.RawMessage(strings.Replace(clients, "%s", id, 1)),
			"customDomains":   json.RawMessage(`[{"domain":"login.example.test","type":"self_managed_certs","relying_party_identifier":"` + domainRP + `"}]`),
			"guardianFactors": json.RawMessage(`[{"name":"webauthn-roaming","enabled":` + roaming + `},{"name":"webauthn-platform","enabled":true}]`),
		}}
	}
	source := makeExport("source", "example.test", "true")
	if r := Compare(source, makeExport("target", "example.test", "true"), m, Domains{}); !r.Equivalent {
		t.Fatalf("equal passkey fields differ: %+v", r.Differences)
	}
	if Compare(source, makeExport("target", "login.example.test", "true"), m, Domains{}).Equivalent {
		t.Fatal("changed relying_party_identifier accepted")
	}
	if Compare(source, makeExport("target", "example.test", "false"), m, Domains{}).Equivalent {
		t.Fatal("changed WebAuthn factor accepted")
	}
	for _, edit := range []func(row map[string]any){
		func(row map[string]any) { delete(row, "mobile") },
		func(row map[string]any) { row["mobile"].(map[string]any)["ios"].(map[string]any)["team_id"] = "OTHER" },
		func(row map[string]any) { row["grant_types"] = []any{"authorization_code"} },
	} {
		target := makeExport("target", "example.test", "true")
		var rows []map[string]any
		_ = json.Unmarshal(target.Resources["clients"], &rows)
		edit(rows[0])
		target.Resources["clients"], _ = json.Marshal(rows)
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatalf("lost client passkey field accepted: %s", target.Resources["clients"])
		}
	}
}

// passkeyAPI routes the Management operations the pinned handlers call to
// the real handlers. Authorization is not under test; tenancy is fixed.
type passkeyAPI struct {
	mgmtapi.Unimplemented
	h *mgmt.Handlers
}

func (a passkeyAPI) GetClients(w http.ResponseWriter, r *http.Request, p mgmtapi.GetClientsParams) {
	a.h.GetClients(w, r, p)
}
func (a passkeyAPI) CreateClient(w http.ResponseWriter, r *http.Request) { a.h.CreateClient(w, r) }
func (a passkeyAPI) GetClient(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetClientParams) {
	a.h.GetClient(w, r, id, p)
}
func (a passkeyAPI) UpdateClient(w http.ResponseWriter, r *http.Request, id string) {
	a.h.UpdateClient(w, r, id)
}
func (a passkeyAPI) GetConnections(w http.ResponseWriter, r *http.Request, p mgmtapi.GetConnectionsParams) {
	a.h.GetConnections(w, r, p)
}
func (a passkeyAPI) CreateConnection(w http.ResponseWriter, r *http.Request) {
	a.h.CreateConnection(w, r)
}
func (a passkeyAPI) GetConnection(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionParams) {
	a.h.GetConnection(w, r, id, p)
}
func (a passkeyAPI) UpdateConnection(w http.ResponseWriter, r *http.Request, id string) {
	a.h.UpdateConnection(w, r, id)
}
func (a passkeyAPI) GetConnectionClients(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionClientsParams) {
	a.h.GetConnectionClients(w, r, id, p)
}
func (a passkeyAPI) UpdateConnectionClients(w http.ResponseWriter, r *http.Request, id string) {
	a.h.UpdateConnectionClients(w, r, id)
}
func (a passkeyAPI) GetActions(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetActionsParams) {
	a.h.GetActions(w, r)
}
func (a passkeyAPI) GetCustomDomains(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetCustomDomainsParams) {
	a.h.GetCustomDomains(w, r)
}
func (a passkeyAPI) CreateCustomDomain(w http.ResponseWriter, r *http.Request) {
	a.h.CreateCustomDomain(w, r)
}
func (a passkeyAPI) GetCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	a.h.GetCustomDomain(w, r, id)
}
func (a passkeyAPI) UpdateCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	a.h.UpdateCustomDomain(w, r, id)
}
func (a passkeyAPI) GetGuardianFactors(w http.ResponseWriter, r *http.Request) {
	a.h.MFAOperation(w, r, "GetGuardianFactors", "", "")
}
func (a passkeyAPI) SetGuardianFactor(w http.ResponseWriter, r *http.Request, name mgmtapi.SetGuardianFactorParamsName) {
	a.h.MFAOperation(w, r, "SetGuardianFactor", "", string(name))
}

// deployScopes are the scopes a Deploy CLI machine client holds for these
// handlers; handlers that check a scope internally see them.
var deployScopes = []string{
	"read:clients", "create:clients", "update:clients",
	"read:connections", "create:connections", "update:connections",
	"read:custom_domains", "create:custom_domains", "update:custom_domains",
	"read:guardian_factors", "update:guardian_factors", "read:actions",
}

// TestPinnedPasskeyHandlers is a focused Management boundary test, separate
// from the four-cell Deploy CLI acceptance lane (Task 19 runs that on every
// backend). The script checks the installed versions; no tool method,
// response shape or status is adapted.
func TestPinnedPasskeyHandlers(t *testing.T) {
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
	now := func() time.Time { return time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC) }
	domains := customdomain.NewService(st, nil, customdomain.ServiceConfig{BaseDomain: "auth.zeroauthy.test", OriginDomain: "origin.zeroauthy.test", OriginTLSReady: true}, now, rand.Reader)
	h := &mgmt.Handlers{Store: st, Wrapper: wrapper, Log: slog.Default(), Domains: domains, BaseDomain: "auth.zeroauthy.test", Now: now}
	api := mgmtapi.Handler(passkeyAPI{h: h})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: r.Host})
		ctx = mgmt.WithCaller(ctx, mgmt.Caller{Kind: mgmt.M2M, ClientID: "deploy-cli", Scopes: deployScopes})
		api.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "passkey-pinned-roundtrip.cjs", strings.TrimPrefix(srv.URL, "https://"))
	cmd.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+cert, "ZA_DEPLOY_CLI_MODULES="+modules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pinned handlers: %v\n%s", err, out)
	}
	t.Log(string(out))
	// The server state agrees with what the tool exported.
	c, _, err := st.Clients().List(ctx, tn.ID, store.ClientFilter{}, store.Page{Limit: 50})
	if err != nil || len(c) != 1 || c[0].Mobile == nil || c[0].Mobile.IOS.TeamID != "FGHIJ67890" {
		t.Fatalf("stored client = %+v (%v)", c, err)
	}
}
