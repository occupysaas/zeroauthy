package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type proofDNS map[string]string

func (p proofDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := p[name]; ok {
		return []string{v}, nil
	}
	return nil, customdomain.ErrDNSNotFound
}
func (proofDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", customdomain.ErrDNSNotFound
}
func (proofDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, customdomain.ErrDNSNotFound
}

// A self-managed domain behind an authenticated proxy is served as its
// public origin; rejected requests stop before any handler.
func TestServerCustomDomainAdmission(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	dns := proofDNS{}
	svc := customdomain.NewService(st, dns, customdomain.ServiceConfig{
		OriginDomain: "origin.example.test", OriginTLSReady: true,
		Proxy: customdomain.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
	}, time.Now, rand.Reader)
	h, st2 := newMgmtEnvOn(t, st, mgmtSeed, func(d *Deps) { d.Domains = svc })
	acme, _ := st2.Tenants().GetByName(ctx, "acme")
	d, err := svc.Create(ctx, acme.ID, customdomain.CreateInput{Domain: "id.acme.test", Type: customdomain.TypeSelfManaged,
		CustomClientIPHeader: customdomain.Field[string]{Value: "true-client-ip"}})
	if err != nil {
		t.Fatal(err)
	}
	dns[d.ProofRecordName] = customdomain.ProofValue(d)
	res, err := svc.Verify(ctx, acme.ID, d.ID)
	if err != nil || res.CNAMEAPIKey == "" {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	req := func(key, clientIP string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://"+d.OriginHost+"/.well-known/openid-configuration", nil)
		r.RemoteAddr = "198.51.100.7:40000"
		r.TLS = &tls.ConnectionState{ServerName: d.OriginHost}
		r.Header.Set("X-Forwarded-Host", "acme.example.test")
		if key != "" {
			r.Header.Set(customdomain.ProxyKeyHeader, key)
		}
		if clientIP != "" {
			r.Header.Set("true-client-ip", clientIP)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := req(res.CNAMEAPIKey, "203.0.113.9")
	var doc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if rec.Code != 200 || doc["issuer"] != "https://id.acme.test/" {
		t.Fatalf("discovery = %d %v", rec.Code, doc)
	}
	if rec := req("", "203.0.113.9"); rec.Code != http.StatusForbidden {
		t.Errorf("no key = %d", rec.Code)
	}
	if rec := req(res.CNAMEAPIKey, "203.0.113.9, 10.0.0.1"); rec.Code != http.StatusBadRequest {
		t.Errorf("client IP list = %d", rec.Code)
	}
	// An ordinary host cannot be steered to the custom domain by a forwarded
	// host, and keeps working.
	r := httptest.NewRequest("GET", "https://acme.example.test/.well-known/openid-configuration", nil)
	r.Header.Set("X-Forwarded-Host", d.Domain)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if rec.Code != 200 || doc["issuer"] != "https://acme.example.test/" {
		t.Fatalf("canonical = %d %v", rec.Code, doc)
	}
}
