package customdomain_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const proxyPeer = "198.51.100.7"

// proxyFixture has an active self-managed domain behind a trusted proxy CIDR,
// with the given client IP header.
func proxyFixture(t *testing.T, header string, legacy bool) (*fixture, *customdomain.Service, *store.CustomDomain, string) {
	t.Helper()
	f := newFixture(t)
	cfg := customdomain.ServiceConfig{
		BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true, OriginTLSReady: true,
		Proxy: customdomain.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, LegacyTrust: legacy},
	}
	svc := customdomain.NewService(f.st, f.dns, cfg, f.clk.now, rand.Reader)
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeSelfManaged)
	if _, err := svc.Update(context.Background(), "acme", d.ID, customdomain.PatchInput{CustomClientIPHeader: customdomain.Field[string]{Present: true, Value: header}}); err != nil {
		t.Fatal(err)
	}
	f.publish(d)
	res, err := svc.Verify(context.Background(), "acme", d.ID)
	if err != nil || res.CNAMEAPIKey == "" {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	return f, svc, res.Domain, res.CNAMEAPIKey
}

type seen struct {
	host, ip string
	header   http.Header
	called   bool
}

func serve(svc *customdomain.Service, r *http.Request) (*httptest.ResponseRecorder, *seen) {
	got := &seen{}
	h := svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called, got.host, got.ip, got.header = true, r.Host, httpx.ClientIP(r, true), r.Header.Clone()
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, got
}

func proxied(host, peer, key string) *http.Request {
	r := httptest.NewRequest("GET", "https://"+host+"/authorize", nil)
	r.RemoteAddr = peer + ":40000"
	r.TLS = &tls.ConnectionState{ServerName: host}
	if key != "" {
		r.Header.Set("cname-api-key", key)
	}
	return r
}

func TestDomainProxyAdmission(t *testing.T) {
	f, svc, d, key := proxyFixture(t, "x-forwarded-for", false)
	for _, host := range []string{d.OriginHost, d.Domain} {
		r := proxied(host, proxyPeer, key)
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Forwarded-Host", "globex.auth.example.test")
		r.Header.Set("Forwarded", "host=evil.test")
		rec, got := serve(svc, r)
		if !got.called || got.host != "login.acme.test" || got.ip != "203.0.113.9" {
			t.Fatalf("%s: %d %+v", host, rec.Code, got)
		}
		for _, h := range []string{"cname-api-key", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded"} {
			if got.header.Get(h) != "" {
				t.Errorf("%s: header %s reached the handler", host, h)
			}
		}
		again := proxied(host, proxyPeer, key)
		again.Header.Set("X-Forwarded-For", "203.0.113.9")
		adm, err := svc.Admit(again)
		if err != nil || adm.TenantID != "acme" || adm.DomainID != d.ID || adm.PublicHost != d.Domain {
			t.Fatalf("admit %s = %+v, %v", host, adm, err)
		}
	}
	g := f.create(t, "globex", "login.globex.test", customdomain.TypeSelfManaged)
	f.publish(g)
	f.clk.add(time.Minute)
	gres, err := svc.Verify(context.Background(), "globex", g.ID)
	if err != nil || gres.CNAMEAPIKey == "" {
		t.Fatalf("globex verify = %+v, %v", gres, err)
	}
	okey := gres.CNAMEAPIKey
	for name, r := range map[string]*http.Request{
		"no key":        proxied(d.OriginHost, proxyPeer, ""),
		"wrong key":     proxied(d.OriginHost, proxyPeer, key+"x"),
		"foreign key":   proxied(d.OriginHost, proxyPeer, okey),
		"untrusted":     proxied(d.OriginHost, "192.0.2.50", key),
		"public no key": proxied(d.Domain, proxyPeer, ""),
	} {
		rec, got := serve(svc, r)
		if got.called || rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d called=%v", name, rec.Code, got.called)
		}
	}
	plain := proxied(d.OriginHost, proxyPeer, key)
	plain.TLS = nil
	if rec, got := serve(svc, plain); got.called || rec.Code != http.StatusForbidden {
		t.Errorf("plaintext origin: %d", rec.Code)
	}
	// Unknown custom names fail closed; ordinary hosts pass through untouched.
	if _, err := svc.Admit(proxied("nobody.acme.test", proxyPeer, key)); !errors.Is(err, customdomain.ErrNotCustomDomain) {
		t.Errorf("unknown = %v", err)
	}
	r := httptest.NewRequest("GET", "https://acme.auth.example.test/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if rec, got := serve(svc, r); !got.called || got.host != "acme.auth.example.test" || got.ip == "203.0.113.9" {
		t.Errorf("canonical without legacy trust: %d %+v", rec.Code, got)
	}
}

// Pending or deleted names never admit, even with the right key: they fail
// closed in admission or in tenant resolution behind it.
func TestDomainProxyAdmissionRequiresReady(t *testing.T) {
	f, svc, d, key := proxyFixture(t, "", false)
	h := svc.Middleware(tenant.NewResolver(f.st.Tenants(), "auth.example.test", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("served %s", r.Host)
	})))
	code := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	p := f.create(t, "acme", "pending.acme.test", customdomain.TypeSelfManaged)
	for _, host := range []string{p.OriginHost, p.Domain} {
		if c := code(proxied(host, proxyPeer, key)); c != http.StatusNotFound {
			t.Errorf("pending %s: %d", host, c)
		}
	}
	if err := svc.Delete(context.Background(), "acme", d.ID); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{d.OriginHost, d.Domain} {
		if c := code(proxied(host, proxyPeer, key)); c != http.StatusNotFound {
			t.Errorf("deleted %s: %d", host, c)
		}
	}
}

func TestDomainClientIP(t *testing.T) {
	for _, tc := range []struct {
		header string
		values []string
		code   int
		want   string
	}{
		{"x-forwarded-for", []string{"203.0.113.9"}, 200, "203.0.113.9"},
		{"cf-connecting-ip", []string{"2001:db8::1"}, 200, "2001:db8::1"},
		{"true-client-ip", []string{"203.0.113.9, 203.0.113.10"}, 400, ""},
		{"true-client-ip", []string{"203.0.113.9", "203.0.113.10"}, 400, ""},
		{"true-client-ip", []string{"203.0.113.9:443"}, 400, ""},
		{"true-client-ip", []string{"fe80::1%eth0"}, 400, ""},
		{"true-client-ip", []string{"not-an-ip"}, 400, ""},
		{"true-client-ip", nil, 400, ""},
		{"", []string{"203.0.113.9"}, 200, proxyPeer}, // disabled: the peer
	} {
		_, svc, d, key := proxyFixture(t, tc.header, false)
		r := proxied(d.OriginHost, proxyPeer, key)
		name := tc.header
		if name == "" {
			name = "true-client-ip"
		}
		for _, v := range tc.values {
			r.Header.Add(name, v)
		}
		rec, got := serve(svc, r)
		if rec.Code != tc.code && !(tc.code == 200 && got.called) || tc.code == 200 && got.ip != tc.want {
			t.Errorf("%s %q: %d ip=%q", tc.header, tc.values, rec.Code, got.ip)
		}
		if tc.code != 200 && got.called {
			t.Errorf("%s %q reached the handler", tc.header, tc.values)
		}
		if tc.code == 200 && got.header.Get(name) != "" {
			t.Errorf("%s: client IP header reached the handler", tc.header)
		}
	}
}

func TestDomainHostSNI(t *testing.T) {
	f, svc, d, key := proxyFixture(t, "", false)
	r := proxied(d.OriginHost, proxyPeer, key)
	r.TLS.ServerName = "other.auth.example.test"
	if rec, got := serve(svc, r); got.called || rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("origin SNI mismatch: %d", rec.Code)
	}
	// A ready managed domain is served directly: Host must equal SNI, and
	// forwarded headers are ignored.
	m := f.create(t, "acme", "id.acme.test", customdomain.TypeManaged)
	cur := f.get(t, m)
	cur.Lifecycle, cur.Status, cur.ProofStatus = customdomain.LifecycleActive, customdomain.StatusReady, customdomain.ProofVerified
	ctx := context.Background()
	if err := f.st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.CustomDomains().Update(ctx, cur, cur.Revision); err != nil {
			return err
		}
		return tx.CustomDomains().PutHost(ctx, &store.HostBinding{Host: cur.Domain, TenantID: "acme", DomainID: cur.ID, Generation: cur.Generation, Kind: store.HostPublic, Active: true})
	}); err != nil {
		t.Fatal(err)
	}
	direct := proxied("id.acme.test", "192.0.2.50", "")
	direct.Header.Set("X-Forwarded-For", "203.0.113.9")
	direct.Header.Set("X-Forwarded-Host", "acme.auth.example.test")
	rec, got := serve(svc, direct)
	if !got.called || got.host != "id.acme.test" || got.ip != "192.0.2.50" {
		t.Fatalf("managed direct: %d %+v", rec.Code, got)
	}
	mismatch := proxied("id.acme.test", "192.0.2.50", "")
	mismatch.TLS.ServerName = "login.acme.test"
	if rec, got := serve(svc, mismatch); got.called || rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("managed SNI mismatch: %d", rec.Code)
	}
}

// Legacy forwarded trust stays in its documented mode, constrained to the
// trusted CIDRs, and can never reach an API custom domain or origin.
func TestDomainLegacyProxyTrust(t *testing.T) {
	_, svc, d, _ := proxyFixture(t, "", true)
	for _, tc := range []struct {
		peer, fwdHost string
		code          int
		host, ip      string
	}{
		{proxyPeer, "globex.auth.example.test", 200, "globex.auth.example.test", "203.0.113.9"},
		{"192.0.2.50", "globex.auth.example.test", 200, "acme.auth.example.test", "192.0.2.50"},
		{proxyPeer, d.Domain, http.StatusMisdirectedRequest, "", ""},
		{proxyPeer, d.OriginHost, http.StatusMisdirectedRequest, "", ""},
	} {
		r := httptest.NewRequest("GET", "https://acme.auth.example.test/", nil)
		r.RemoteAddr = tc.peer + ":40000"
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Forwarded-Host", tc.fwdHost)
		rec, got := serve(svc, r)
		if tc.code != 200 {
			if got.called || rec.Code != tc.code {
				t.Errorf("%s via %s: %d", tc.fwdHost, tc.peer, rec.Code)
			}
			continue
		}
		fwd := got.header.Get("X-Forwarded-Host")
		host := got.host
		if fwd != "" {
			host = fwd
		}
		if !got.called || host != tc.host || got.ip != tc.ip {
			t.Errorf("%s via %s: %d host=%s ip=%s", tc.fwdHost, tc.peer, rec.Code, host, got.ip)
		}
	}
}
