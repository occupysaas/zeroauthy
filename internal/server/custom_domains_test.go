package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const domainScopes = `"read:custom_domains", "create:custom_domains", "update:custom_domains", "delete:custom_domains"`

type domainsEnv struct {
	h      http.Handler
	st     store.Store
	dns    proofDNS
	token  string
	reader string
	acme   *store.Tenant
}

func newDomainsEnv(t *testing.T, cfg customdomain.ServiceConfig) *domainsEnv {
	return newDomainsEnvLog(t, cfg, io.Discard)
}

func newDomainsEnvLog(t *testing.T, cfg customdomain.ServiceConfig, logs io.Writer) *domainsEnv {
	t.Helper()
	st := memory.New()
	dns := proofDNS{}
	svc := customdomain.NewService(st, dns, cfg, time.Now, rand.Reader)
	seed := strings.Replace(mgmtSeed, `"read:connections", "create:connections", "update:connections", "delete:connections"]`,
		`"read:connections", "create:connections", "update:connections", "delete:connections", `+domainScopes+`]`, 1)
	seed = strings.Replace(seed, `scopes: ["read:clients", "read:resource_servers"]`, `scopes: ["read:clients", "read:resource_servers", "read:custom_domains"]`, 1)
	h, _ := newMgmtEnvOn(t, st, seed, func(d *Deps) {
		d.Domains = svc
		d.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	acme, _ := st.Tenants().GetByName(context.Background(), "acme")
	return &domainsEnv{h: h, st: st, dns: dns, acme: acme,
		token:  clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret"),
		reader: m2mToken(t, h, "acme.example.test", acmeMgmtAPI)}
}

func (e *domainsEnv) call(method, path, token, body string) (*httptest.ResponseRecorder, any) {
	r := httptest.NewRequest(method, "https://acme.example.test/api/v2/custom-domains"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	var out any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func TestCustomDomainManagementContract(t *testing.T) {
	cfg := customdomain.ServiceConfig{OriginDomain: "origin.example.test", ManagedEnabled: true, OriginTLSReady: true, SystemHost: mgmtSystemHost,
		Proxy: customdomain.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}}
	e := newDomainsEnv(t, cfg)

	// Scopes.
	if rec, _ := e.call("POST", "", e.reader, `{"domain":"id.acme.test","type":"auth0_managed_certs"}`); rec.Code != 403 {
		t.Fatalf("create with read scope = %d", rec.Code)
	}
	if rec, _ := e.call("GET", "", "", ""); rec.Code != 401 {
		t.Fatalf("no token = %d", rec.Code)
	}

	// Create: pending, with public proof instructions only.
	rec, out := e.call("POST", "", e.token, `{"domain":"ID.acme.test.","type":"auth0_managed_certs","domain_metadata":{"brand":"Acme"}}`)
	m := obj(out)
	if rec.Code != 201 || m["domain"] != "id.acme.test" || m["status"] != "pending_verification" || m["is_default"] != false || m["primary"] != false ||
		m["tls_policy"] != "recommended" || m["custom_client_ip_header"] != "x-forwarded-for" || m["relying_party_identifier"] != "id.acme.test" {
		t.Fatalf("create = %d %v", rec.Code, out)
	}
	id := m["custom_domain_id"].(string)
	ver := obj(m["verification"])
	methods, _ := ver["methods"].([]any)
	method := obj(methods[0])
	if ver["status"] != "pending" || method["name"] != "txt" || method["domain"] != "_zeroauthy-domain-verification.id.acme.test" ||
		!strings.HasPrefix(method["record"].(string), "zeroauthy-domain-verification=") || !strings.HasSuffix(m["origin_domain_name"].(string), ".origin.example.test") {
		t.Fatalf("verification = %v origin=%v", ver, m["origin_domain_name"])
	}
	if _, ok := m["cname_api_key"]; ok {
		t.Fatal("create returned a proxy key")
	}

	// Validation and conflicts.
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"duplicate":      {`{"domain":"id.acme.test","type":"auth0_managed_certs"}`, 409},
		"unknown field":  {`{"domain":"x.acme.test","type":"auth0_managed_certs","extra":1}`, 400},
		"null domain":    {`{"domain":null,"type":"auth0_managed_certs"}`, 400},
		"wildcard":       {`{"domain":"*.acme.test","type":"auth0_managed_certs"}`, 400},
		"port":           {`{"domain":"x.acme.test:443","type":"auth0_managed_certs"}`, 400},
		"system host":    {`{"domain":"` + mgmtSystemHost + `","type":"auth0_managed_certs"}`, 400},
		"origin space":   {`{"domain":"a.origin.example.test","type":"auth0_managed_certs"}`, 400},
		"bad header":     {`{"domain":"x.acme.test","type":"auth0_managed_certs","custom_client_ip_header":"x-real-ip"}`, 400},
		"metadata value": {`{"domain":"x.acme.test","type":"auth0_managed_certs","domain_metadata":{"a":"` + strings.Repeat("é", 256) + `"}}`, 400},
		"too large":      {`{"domain":"x.acme.test","type":"auth0_managed_certs","domain_metadata":{"a":"` + strings.Repeat("a", 70000) + `"}}`, 413},
		"canonical host": {`{"domain":"acme.example.test","type":"auth0_managed_certs"}`, 409},
	} {
		if rec, out := e.call("POST", "", e.token, tc.body); rec.Code != tc.code {
			t.Errorf("%s = %d %v", name, rec.Code, out)
		}
	}

	// Reads, list query and projection.
	if rec, out := e.call("GET", "/"+id, e.reader, ""); rec.Code != 200 || obj(out)["domain"] != "id.acme.test" {
		t.Fatalf("get = %d %v", rec.Code, out)
	}
	if rec, _ := e.call("GET", "/cd_nope", e.reader, ""); rec.Code != 404 {
		t.Fatalf("missing = %d", rec.Code)
	}
	rec, out = e.call("GET", `?q=domain:"id.acme.test"&fields=domain,status&include_fields=true`, e.reader, "")
	list, _ := out.([]any)
	if rec.Code != 200 || len(list) != 1 || len(obj(list[0])) != 2 || obj(list[0])["status"] != "pending_verification" {
		t.Fatalf("list = %d %v", rec.Code, out)
	}
	if rec, _ := e.call("GET", `?q=domain:id.acme.test`, e.reader, ""); rec.Code != 400 {
		t.Fatalf("unquoted query = %d", rec.Code)
	}

	// Update: null and empty header are distinct stored values.
	if rec, out := e.call("PATCH", "/"+id, e.token, `{"custom_client_ip_header":null,"domain_metadata":{}}`); rec.Code != 200 || obj(out)["custom_client_ip_header"] != nil || len(obj(obj(out)["domain_metadata"])) != 0 {
		t.Fatalf("patch null = %d %v", rec.Code, out)
	}
	if rec, out := e.call("PATCH", "/"+id, e.token, `{"custom_client_ip_header":""}`); rec.Code != 200 || obj(out)["custom_client_ip_header"] != "" {
		t.Fatalf("patch empty = %d %v", rec.Code, out)
	}
	if rec, _ := e.call("PATCH", "/"+id, e.token, `{"domain":"other.acme.test"}`); rec.Code != 400 {
		t.Fatalf("patch domain = %d", rec.Code)
	}

	// Default: literal route precedence, canonical shape, readiness required.
	if rec, out := e.call("GET", "/default", e.reader, ""); rec.Code != 200 || obj(out)["domain"] != "acme.example.test" || len(obj(out)) != 1 {
		t.Fatalf("default = %d %v", rec.Code, out)
	}
	if rec, _ := e.call("PATCH", "/default", e.token, `{"domain":"id.acme.test"}`); rec.Code != 409 {
		t.Fatalf("pending default = %d", rec.Code)
	}
	if rec, _ := e.call("PATCH", "/default", e.token, `{"domain":"nobody.acme.test"}`); rec.Code != 404 {
		t.Fatalf("unknown default = %d", rec.Code)
	}

	// Verify without proof stays pending; a second attempt is rate limited.
	if rec, out := e.call("POST", "/"+id+"/verify", e.token, ""); rec.Code != 200 || obj(out)["status"] != "pending_verification" {
		t.Fatalf("verify = %d %v", rec.Code, out)
	}
	if rec, _ := e.call("POST", "/"+id+"/verify", e.token, ""); rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit = %d %v", rec.Code, rec.Header())
	}
	if rec, _ := e.call("POST", "/"+id+"/test", e.token, ""); rec.Code != 409 {
		t.Fatalf("test pending = %d", rec.Code)
	}

	// Self-managed: the first successful verify alone returns the key.
	rec, out = e.call("POST", "", e.token, `{"domain":"proxy.acme.test","type":"self_managed_certs"}`)
	sm := obj(out)
	smID := sm["custom_domain_id"].(string)
	e.dns[obj(obj(sm["verification"])["methods"].([]any)[0])["domain"].(string)] = obj(obj(sm["verification"])["methods"].([]any)[0])["record"].(string)
	rec, out = e.call("POST", "/"+smID+"/verify", e.token, "")
	key, _ := obj(out)["cname_api_key"].(string)
	if rec.Code != 200 || obj(out)["status"] != "ready" || key == "" {
		t.Fatalf("self-managed verify = %d %v", rec.Code, out)
	}
	if rec, out := e.call("POST", "/"+smID+"/verify", e.token, ""); rec.Code != 200 || obj(out)["cname_api_key"] != nil {
		t.Fatalf("repeat verify = %d %v", rec.Code, out)
	}
	if _, ok := obj(sm)["certificate"]; ok {
		t.Error("self-managed domain reports a certificate")
	}
	// Default to a ready domain and back to canonical.
	if rec, out := e.call("PATCH", "/default", e.token, `{"domain":"proxy.acme.test"}`); rec.Code != 200 || obj(out)["is_default"] != true {
		t.Fatalf("set default = %d %v", rec.Code, out)
	}
	if rec, out := e.call("GET", "/default", e.reader, ""); rec.Code != 200 || obj(out)["custom_domain_id"] != smID {
		t.Fatalf("get default = %d %v", rec.Code, out)
	}
	if rec, out := e.call("PATCH", "/default", e.token, `{"domain":"acme.example.test"}`); rec.Code != 200 || obj(out)["domain"] != "acme.example.test" {
		t.Fatalf("canonical default = %d %v", rec.Code, out)
	}

	// Secrets never appear in any read.
	for _, path := range []string{"", "/" + smID, "/default"} {
		rec, _ := e.call("GET", path, e.reader, "")
		body := rec.Body.String()
		for _, secret := range []string{key, "proxy_key", "ProxyKeyHash", "proof_token", "ProofToken", "Generation", "Lifecycle"} {
			if strings.Contains(body, secret) {
				t.Errorf("GET %q leaks %q", path, secret)
			}
		}
	}

	// Delete.
	if rec, _ := e.call("DELETE", "/"+id, e.token, ""); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec, _ := e.call("GET", "/"+id, e.reader, ""); rec.Code != 404 {
		t.Fatalf("after delete = %d", rec.Code)
	}
	if rec, _ := e.call("DELETE", "/"+id, e.token, ""); rec.Code != 404 {
		t.Fatalf("delete again = %d", rec.Code)
	}
}

func TestCustomDomainManagementLimits(t *testing.T) {
	e := newDomainsEnv(t, customdomain.ServiceConfig{OriginDomain: "origin.example.test"})
	if rec, out := e.call("POST", "", e.token, `{"domain":"id.acme.test","type":"auth0_managed_certs"}`); rec.Code != 503 {
		t.Fatalf("managed without ACME = %d %v", rec.Code, out)
	}
	if rec, out := e.call("POST", "", e.token, `{"domain":"id.acme.test","type":"self_managed_certs"}`); rec.Code != 503 {
		t.Fatalf("self-managed without origin TLS = %d %v", rec.Code, out)
	}
	e = newDomainsEnv(t, customdomain.ServiceConfig{OriginDomain: "origin.example.test", ManagedEnabled: true})
	for i := range 100 {
		if rec, out := e.call("POST", "", e.token, fmt.Sprintf(`{"domain":"d%d.acme.test","type":"auth0_managed_certs"}`, i)); rec.Code != 201 {
			t.Fatalf("domain %d = %d %v", i, rec.Code, out)
		}
	}
	if rec, _ := e.call("POST", "", e.token, `{"domain":"d100.acme.test","type":"auth0_managed_certs"}`); rec.Code != 409 {
		t.Fatalf("101st = %d", rec.Code)
	}
}

// The one-time proxy key appears in the winning verify response only: not in
// logs, later reads, lists, the default view or a repeated verify.
func TestDomainSecretExposure(t *testing.T) {
	var logs bytes.Buffer
	e := newDomainsEnvLog(t, customdomain.ServiceConfig{OriginDomain: "origin.example.test", OriginTLSReady: true}, &logs)
	_, out := e.call("POST", "", e.token, `{"domain":"proxy.acme.test","type":"self_managed_certs"}`)
	d := obj(out)
	m := obj(obj(d["verification"])["methods"].([]any)[0])
	e.dns[m["domain"].(string)] = m["record"].(string)
	_, out = e.call("POST", "/"+d["custom_domain_id"].(string)+"/verify", e.token, "")
	key, _ := obj(out)["cname_api_key"].(string)
	if key == "" {
		t.Fatalf("verify = %v", out)
	}
	if _, out := e.call("PATCH", "/default", e.token, `{"domain":"proxy.acme.test"}`); obj(out)["cname_api_key"] != nil {
		t.Fatal("default response carries the key")
	}
	var bodies []string
	for _, p := range []string{"", "/" + d["custom_domain_id"].(string), "/default"} {
		rec, _ := e.call("GET", p, e.reader, "")
		bodies = append(bodies, rec.Body.String())
	}
	rec, _ := e.call("POST", "/"+d["custom_domain_id"].(string)+"/verify", e.token, "")
	bodies = append(bodies, rec.Body.String(), logs.String())
	stored, _ := e.st.CustomDomains().Get(context.Background(), e.acme.ID, d["custom_domain_id"].(string))
	for i, b := range bodies {
		if strings.Contains(b, key) || strings.Contains(b, "cname_api_key") || strings.Contains(b, fmt.Sprintf("%x", stored.ProxyKeyHash)) {
			t.Errorf("output %d exposes the key or its hash", i)
		}
	}
}

func TestExpiredManagedDomainReadProjection(t *testing.T) {
	e := newDomainsEnv(t, customdomain.ServiceConfig{ManagedEnabled: true})
	rec, out := e.call("POST", "", e.token, `{"domain":"expired.acme.test","type":"auth0_managed_certs"}`)
	if rec.Code != 201 {
		t.Fatal(rec.Code, out)
	}
	ctx := context.Background()
	id := obj(out)["custom_domain_id"].(string)
	d, _ := e.st.CustomDomains().Get(ctx, e.acme.ID, id)
	a := &store.TLSAsset{Key: "cert/expired-projection", Kind: store.TLSAssetCertificate, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, PublicData: store.TLSPublicData{Version: 1, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(-time.Second)}}
	if err := e.st.TLSAssets().Put(ctx, a, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.st.WithTx(ctx, func(tx store.Store) error {
		return customdomain.ActivateManaged(ctx, tx, d, a.Key, time.Now(), time.Now().Add(time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	rec, out = e.call("GET", "/"+id, e.token, "")
	if rec.Code != 200 || obj(out)["status"] == "ready" {
		t.Fatalf("expired certificate advertised ready: %d %v", rec.Code, out)
	}
}
