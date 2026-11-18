package server

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/console"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestConsoleServedOnSystemHost(t *testing.T) {
	h := newMgmtServer(t)
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
		return rec
	}
	sys := "https://" + mgmtSystemHost

	if rec := get(sys + "/admin"); rec.Code != 301 || rec.Header().Get("Location") != "/admin/" {
		t.Errorf("/admin = %d %v", rec.Code, rec.Header())
	}
	index, err := fs.ReadFile(console.Files(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	// The index and every deep link (Review Focus 5) answer the console.
	for _, p := range []string{"/admin/", "/admin/callback?code=x&state=y", "/admin/t/acme/applications/xyz", "/admin/t/acme/"} {
		rec := get(sys + p)
		if rec.Code != 200 || regexp.MustCompile(`<meta name="zeroauthy-preview-style-nonce" content="[A-Za-z0-9_-]{22}">`).ReplaceAllString(rec.Body.String(), "") != string(index) || rec.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s = %d %q", p, rec.Code, rec.Header().Get("Cache-Control"))
		}
		csp := rec.Header().Get("Content-Security-Policy")
		nonce := regexp.MustCompile(`<meta name="zeroauthy-preview-style-nonce" content="([A-Za-z0-9_-]{22})">`).FindStringSubmatch(rec.Body.String())
		if len(nonce) != 2 || !strings.Contains(csp, "style-src 'self' 'nonce-"+nonce[1]+"'") {
			t.Fatal("preview style nonce not bound to document CSP")
		}

		for _, want := range []string{"script-src 'self'", "frame-ancestors 'none'", "default-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", p, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP allows inline code: %q", p, csp)
		}
	}
	// No inline scripts or styles in the built page.
	if regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`).Match(index) || strings.Contains(string(index), "<style") {
		t.Error("index.html has inline script or style")
	}

	asset := regexp.MustCompile(`/admin/(assets/[^"]+\.js)`).FindStringSubmatch(string(index))
	if asset == nil {
		t.Fatalf("no script in %s", index)
	}
	rec := get(sys + "/admin/" + asset[1])
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset = %d %v", rec.Code, rec.Header())
	}
	if rec := get(sys + "/admin/assets/missing.js"); rec.Code != 404 {
		t.Errorf("missing asset = %d", rec.Code)
	}
	// Only on the system host.
	for _, target := range []string{"https://acme.example.test/admin/", "https://acme.example.test/admin/" + asset[1]} {
		if rec := get(target); rec.Code != 404 {
			t.Errorf("%s = %d", target, rec.Code)
		}
	}
}

type adminListProbe struct {
	store.Tenants
	calls int
	err   error
}

func (p *adminListProbe) List(ctx context.Context) ([]*store.Tenant, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return p.Tenants.List(ctx)
}

type adminProbeStore struct {
	store.Store
	tenants *adminListProbe
}

func (s adminProbeStore) Tenants() store.Tenants { return s.tenants }

func TestAdminCSPNoTenantDomains(t *testing.T) {
	for _, tc := range []struct {
		name, base, connect string
	}{
		{"base domain", "EXAMPLE.NET.", "connect-src 'self' https://*.example.net https://admin.example.test"},
		{"custom domains only", "", "connect-src 'self' https://admin.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &adminListProbe{}
			h, st := newMgmtEnvWith(t, func(d *Deps) {
				d.BaseDomain = tc.base
				probe.Tenants = d.Store.Tenants()
				d.Store = adminProbeStore{Store: d.Store, tenants: probe}
				d.Resolver = tenant.NewResolver(probe, tc.base, false)
			})
			get := func(method, path string) {
				t.Helper()
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(method, "https://admin.example.test"+path, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("%s %s = %d", method, path, rec.Code)
				}
				csp := rec.Header().Get("Content-Security-Policy")
				_, connect, _ := strings.Cut(csp, "connect-src ")
				connect, _, _ = strings.Cut(connect, ";")
				if got := "connect-src " + connect; got != tc.connect {
					t.Errorf("%s %s: got %q, want %q", method, path, got, tc.connect)
				}
				if method == http.MethodGet && tc.base != "" && !strings.Contains(rec.Body.String(), `<meta name="zeroauthy-base-domain" content="example.net">`) {
					t.Errorf("%s %s: missing console base domain metadata", method, path)
				}
			}
			get(http.MethodGet, "/admin/")
			if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "ten_later", Name: "later", Domains: []string{"private.partner.test"}}); err != nil {
				t.Fatal(err)
			}
			get(http.MethodGet, "/admin/t/later/applications")
			probe.err = errors.New("tenant enumeration unavailable")
			get(http.MethodHead, "/admin/")
			get(http.MethodGet, "/admin/")
			if probe.calls != 0 {
				t.Errorf("public console called Tenants.List %d times", probe.calls)
			}
		})
	}
}

func TestConsoleManagementProxy(t *testing.T) {
	const custom = "login.partner.test"
	const path = "/api/console/tenants/acme/api/v2/clients"
	const proxy = "https://" + mgmtSystemHost + path
	recorder := &managementRouteRecorder{}
	h, st := newMgmtEnvSeed(t, strings.ReplaceAll(mgmtSeed, "acme.example.test", custom), func(d *Deps) {
		d.Recorder = recorder
		d.Resolver = tenant.NewResolver(d.Store.Tenants(), "example.test", false)
	})
	op, uid := tenantOperatorToken(t, st, "console-proxy@example.test", []string{"acme"})
	systemOnly := mintTargetOperator(t, st, uid, []string{"system"})
	m2m := m2mToken(t, h, custom, "https://"+custom+"/api/v2/")

	t.Run("auth and host boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			name, url, token string
			status           int
		}{
			{"anonymous", proxy, "", 401},
			{"anonymous missing tenant", "https://" + mgmtSystemHost + "/api/console/tenants/missing/api/v2/clients", "", 401},
			{"tenant M2M", proxy, m2m, 401},
			{"signed grant misses target", proxy, systemOnly, 403},
			{"tenant host", "https://" + custom + path, op, 404},
			{"system alias", "https://system.example.test" + path, op, 404},
			{"outside the Management API", "https://" + mgmtSystemHost + "/api/console/tenants/acme/oauth/token", op, 404},
		} {
			if rec, _ := sendRaw(h, "GET", tc.url, tc.token, nil); rec.Code != tc.status {
				t.Errorf("%s = %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body)
			}
		}
		if rec, _ := sendRaw(h, "GET", "https://"+custom+"/api/v2/clients", m2m, nil); rec.Code != 200 {
			t.Errorf("direct M2M = %d %s", rec.Code, rec.Body)
		}
		if rec, _ := sendRaw(h, "POST", "https://"+custom+"/api/v2/clients", m2m, map[string]any{"name": "Missing create scope"}); rec.Code != 403 {
			t.Errorf("direct M2M write without scope = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("target tenant read write and audit", func(t *testing.T) {
		rec, body := sendJSON(h, "GET", proxy+"/%6D2m?fields=client_id&include_fields=true", op, nil)
		if rec.Code != 200 || len(body) != 2 || body["client_id"] != "m2m" || body["tenant"] != "acme" {
			t.Fatalf("projected client = %d %s", rec.Code, rec.Body)
		}
		recorder.events = nil
		rec, body = sendJSON(h, "POST", proxy, op, map[string]any{"name": "Created through the system host"})
		if rec.Code != 201 || body["name"] != "Created through the system host" {
			t.Fatalf("create client = %d %s", rec.Code, rec.Body)
		}
		acme, err := st.Tenants().GetByName(t.Context(), "acme")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := body["client_id"].(string)
		if _, err := st.Clients().Get(t.Context(), acme.ID, id); err != nil {
			t.Fatalf("stored client missing from acme: %v", err)
		}
		if e := recorder.events; len(e) != 1 || e[0].Type != "sapi" || e[0].TenantID != acme.ID || e[0].UserID != uid || e[0].Hostname != custom {
			t.Fatalf("Management audit = %+v", e)
		}
	})

	t.Run("live grant revoked", func(t *testing.T) {
		if err := st.Operators().Upsert(t.Context(), &store.Operator{TenantID: mustSystemID(t, st), UserID: uid, Tenants: []string{"system"}}); err != nil {
			t.Fatal(err)
		}
		if rec, _ := sendRaw(h, "GET", proxy, op, nil); rec.Code != 403 {
			t.Fatalf("revoked target grant = %d %s", rec.Code, rec.Body)
		}
	})
}
