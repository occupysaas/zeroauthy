package customdomain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// These cases catch accepting malformed names or treating equivalent IDNA names
// as different registry claims. Boundary fixtures are measured in DNS bytes.
func TestDomainValidation(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	for _, tt := range []struct {
		raw, want string
		bad       bool
	}{
		{"bücher.example", "xn--bcher-kva.example", false},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", false},
		{"LOGIN.Example.COM.", "login.example.com", false},
		{label63 + ".example", label63 + ".example", false},
		{strings.Repeat("a", 64) + ".example", "", true},
		{name253, name253, false}, {name253 + "b", "", true},
		{"https://login.example.com", "", true}, {"user@login.example.com", "", true},
		{"login.example.com/path", "", true}, {"login.example.com:443", "", true},
		{"127.0.0.1", "", true}, {"[::1]", "", true}, {"*.example.com", "", true},
		{"localhost", "", true}, {"co.uk", "", true}, {"github.io", "", true},
		{"a..example.com", "", true}, {"a.example.com..", "", true},
		{"-a.example.com", "", true}, {"a_.example.com", "", true},
		{" login.example.com", "", true}, {"", "", true},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := NormalizeDNSName(tt.raw)
			if (err != nil) != tt.bad || got != tt.want {
				t.Fatalf("NormalizeDNSName(%q)=(%q,%v), want (%q,bad=%v)", tt.raw, got, err, tt.want, tt.bad)
			}
		})
	}
	reserved := ReservedNames{SystemHost: "system.internal.example", BaseDomain: "tenants.example", OriginSuffix: "origin.example"}
	for _, host := range []string{"system.internal.example", "tenants.example", "a.tenants.example", "origin.example", "a.origin.example"} {
		t.Run("reserved/"+host, func(t *testing.T) {
			_, err := ValidateCreate([]byte(`{"domain":"`+host+`","type":"self_managed_certs"}`), reserved)
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("reserved host accepted: %v", err)
			}
		})
	}
	base := `"domain":"login.customer.example","type":"auth0_managed_certs"`
	create := func(extra string) (CreateInput, error) { return ValidateCreate([]byte(`{`+base+extra+`}`), reserved) }
	t.Run("create defaults", func(t *testing.T) {
		in, err := create("")
		if err != nil {
			t.Fatal(err)
		}
		if in.VerificationMethod.Value != "txt" || in.TLSPolicy.Value != "recommended" || in.CustomClientIPHeader.Value != "x-forwarded-for" || in.RelyingPartyIdentifier.Value != "login.customer.example" || in.CustomClientIPHeader.Present {
			t.Fatalf("wrong create defaults: %+v", in)
		}
	})
	for _, extra := range []string{`,"status":"ready"`, `,"primary":false`, `,"tls_policy":"compatible"`, `,"tls_policy":null`, `,"verification_method":"cname"`, `,"domain_metadata":null`, `,"domain_metadata":{"x":null}`, `,"domain_metadata":{"x":1}`, `,"custom_client_ip_header":"unknown"`, `,"relying_party_identifier":"other.example"`, `,"relying_party_identifier":"example"`, `,"relying_party_identifier":null`, `,"relying_party_identifier":""`} {
		t.Run("bad create/"+extra, func(t *testing.T) {
			if _, err := create(extra); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("accepted %s: %v", extra, err)
			}
		})
	}
	for _, raw := range []string{`{}`, `null`, `[]`, `{"domain":null,"type":"auth0_managed_certs"}`, `{"domain":"login.customer.example","type":""}`, `{"domain":"login.customer.example","domain":"other.example","type":"auth0_managed_certs"}`, `{` + base + `} {}`} {
		if _, err := ValidateCreate([]byte(raw), reserved); err == nil {
			t.Errorf("accepted invalid body %s", raw)
		}
	}
	for _, header := range []string{`null`, `""`, `"true-client-ip"`, `"cf-connecting-ip"`, `"x-forwarded-for"`, `"x-azure-clientip"`} {
		if _, err := create(`,"custom_client_ip_header":` + header); err != nil {
			t.Errorf("header %s: %v", header, err)
		}
	}
	for _, rp := range []string{"login.customer.example", "customer.example"} {
		in, err := create(`,"relying_party_identifier":"` + rp + `"`)
		if err != nil || in.RelyingPartyIdentifier.Value != rp {
			t.Errorf("ancestor RP %q: %+v, %v", rp, in, err)
		}
	}
	for _, n := range []int{255, 256} {
		raw := `,"domain_metadata":{"label":"` + strings.Repeat("界", n) + `"}`
		_, err := create(raw)
		if (err != nil) != (n == 256) {
			t.Errorf("metadata %d characters: %v", n, err)
		}
	}
	for _, n := range []int{10, 11} {
		m := map[string]string{}
		for i := 0; i < n; i++ {
			m[strings.Repeat("k", i+1)] = "v"
		}
		b, _ := json.Marshal(m)
		_, err := create(`,"domain_metadata":` + string(b))
		if (err != nil) != (n == 11) {
			t.Errorf("metadata %d properties: %v", n, err)
		}
	}
	for _, n := range []int{99, 100, 101} {
		err := ValidateDomainCount(n)
		if (err != nil) != (n >= 100) {
			t.Errorf("existing count %d: %v", n, err)
		}
	}
	current := &store.CustomDomain{Domain: "login.customer.example"}
	t.Run("patch presence", func(t *testing.T) {
		in, err := ValidatePatch([]byte(`{"custom_client_ip_header":null,"relying_party_identifier":null,"domain_metadata":{}}`), current)
		if err != nil {
			t.Fatal(err)
		}
		if !in.CustomClientIPHeader.Present || !in.CustomClientIPHeader.Null || in.CustomClientIPHeader.Value != "" || !in.RelyingPartyIdentifier.Null || !in.DomainMetadata.Present || len(in.DomainMetadata.Value) != 0 || in.TLSPolicy.Present {
			t.Fatalf("lost presence: %+v", in)
		}
		empty, err := ValidatePatch([]byte(`{"custom_client_ip_header":""}`), current)
		if err != nil || !empty.CustomClientIPHeader.Present || empty.CustomClientIPHeader.Null {
			t.Fatalf("empty lost: %+v %v", empty, err)
		}
	})
	for _, raw := range []string{`{"domain":"other.example"}`, `{"type":"self_managed_certs"}`, `{"verification_method":"txt"}`, `{"is_default":true}`, `{"certificate":{}}`, `{"domain_metadata":null}`, `{"tls_policy":"compatible"}`, `{"relying_party_identifier":"com"}`} {
		if _, err := ValidatePatch([]byte(raw), current); err == nil {
			t.Errorf("accepted patch %s", raw)
		}
	}
	if _, err := ValidatePatch([]byte(`{}`), nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("nil current: %v", err)
	}
	if _, err := ValidateCreate(bytes.Repeat([]byte(" "), 65537), reserved); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("oversized body: %v", err)
	}
}

// These cases catch parser widening (OR/wildcards/unquoted terms), ignored
// filters, and projection of private registry fields.
func TestDomainQuerySubset(t *testing.T) {
	for _, tt := range []struct {
		q   string
		bad bool
	}{
		{``, false}, {`domain:"login.example.com" AND status:"ready" AND type:"self_managed_certs"`, false},
		{strings.TrimSuffix(strings.Repeat(`status:"ready" AND `, 8), " AND "), false},
		{strings.TrimSuffix(strings.Repeat(`status:"ready" AND `, 9), " AND "), true},
		{`domain:"` + strings.Repeat("a", 1015) + `"`, false},
		{`domain:"` + strings.Repeat("a", 1016) + `"`, true},
		{`domain:login.example.com`, true}, {`domain:"*.example.com"`, true}, {`status:"ready" OR status:"failed"`, true},
		{`internal:"secret"`, true}, {`status:"ready" AND`, true}, {`(status:"ready")`, true}, {`status:"ready" garbage`, true}, {`status:"ready" AND type:"x\"y"`, true},
	} {
		t.Run(tt.q, func(t *testing.T) {
			_, err := ParseQuery(tt.q)
			if (err != nil) != tt.bad {
				t.Fatalf("ParseQuery bad=%v: %v", tt.bad, err)
			}
		})
	}
	terms, err := ParseQuery(`domain:"login.example.com" AND status:"ready"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		row  store.CustomDomain
		want bool
	}{
		{store.CustomDomain{Domain: "login.example.com", Status: "ready"}, true},
		{store.CustomDomain{Domain: "other.example.com", Status: "ready"}, false},
		{store.CustomDomain{Domain: "login.example.com", Status: "failed"}, false},
	} {
		if got := terms.Matches(&tt.row); got != tt.want {
			t.Errorf("Matches(%+v)=%v", tt.row, got)
		}
	}
	for _, v := range []url.Values{
		{"sort": {"domain:-1"}}, {"fields": {"proxy_key_hash"}}, {"fields": {"domain,Generation"}}, {"include_fields": {"maybe"}}, {"q": {"status:\"ready\"", "status:\"failed\""}}, {"unknown": {"x"}},
	} {
		if _, err := ValidateListQuery(v); err == nil {
			t.Errorf("accepted query %v", v)
		}
	}
	in, err := ValidateListQuery(url.Values{"sort": {"domain:1"}, "fields": {"domain,status"}, "include_fields": {"false"}})
	if err != nil || in.IncludeFields || len(in.Fields) != 2 {
		t.Fatalf("valid projection %+v: %v", in, err)
	}
}

// Mutating copies must never change stored ownership, proof, proxy credentials,
// metadata, or encrypted material.
func TestDomainCopies(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*store.CustomDomain)
	}{
		{"metadata", func(d *store.CustomDomain) { d.DomainMetadata["a"] = "changed" }},
		{"proof", func(d *store.CustomDomain) { d.ProofToken[0] = 'X' }},
		{"proxy hash", func(d *store.CustomDomain) { d.ProxyKeyHash[0] = 'X' }},
		{"verified timestamp", func(d *store.CustomDomain) { *d.ProofVerifiedAt = time.Unix(20, 0) }},
		{"proof check timestamp", func(d *store.CustomDomain) { *d.LastProofCheckAt = time.Unix(20, 0) }},
		{"failure timestamp", func(d *store.CustomDomain) { *d.ProofFailureSince = time.Unix(20, 0) }},
		{"next attempt", func(d *store.CustomDomain) { *d.NextAttemptAt = time.Unix(30, 0) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(10, 0)
			original := &store.CustomDomain{DomainMetadata: map[string]string{"a": "original"}, ProofToken: []byte("proof"), ProxyKeyHash: []byte("hash"), ProofVerifiedAt: &now, LastProofCheckAt: &now, ProofFailureSince: &now, NextAttemptAt: &now}
			tt.mutate(original.Clone())
			if original.DomainMetadata["a"] != "original" || string(original.ProofToken) != "proof" || string(original.ProxyKeyHash) != "hash" || original.ProofVerifiedAt.Unix() != 10 || original.LastProofCheckAt.Unix() != 10 || original.ProofFailureSince.Unix() != 10 || original.NextAttemptAt.Unix() != 10 {
				t.Fatalf("domain copy aliases source: %+v", original)
			}
		})
	}
	for _, tt := range []struct {
		name   string
		mutate func(*store.TLSAsset)
	}{
		{"ciphertext", func(a *store.TLSAsset) { a.Ciphertext[0] = 'X' }},
		{"SANs", func(a *store.TLSAsset) { a.PublicData.SANs[0] = "other.example.com" }},
		{"chain", func(a *store.TLSAsset) { a.PublicData.CertificateChainPEM[0] = 'X' }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asset := &store.TLSAsset{Ciphertext: []byte("sealed"), PublicData: store.TLSPublicData{Version: 1, SANs: []string{"login.example.com"}, CertificateChainPEM: []byte("public")}}
			tt.mutate(asset.Clone())
			if string(asset.Ciphertext) != "sealed" || asset.PublicData.SANs[0] != "login.example.com" || string(asset.PublicData.CertificateChainPEM) != "public" {
				t.Fatal("TLS asset copy aliases source")
			}
		})
	}
	if (*store.CustomDomain)(nil).Clone() != nil || (*store.TLSAsset)(nil).Clone() != nil {
		t.Fatal("nil clones changed")
	}
}

func TestDomainRepositoriesUnavailable(t *testing.T) {
	ctx := context.Background()
	domains := store.UnimplementedCustomDomains{}
	assets := store.UnimplementedTLSAssets{}
	checks := []struct {
		name string
		run  func() error
		want error
	}{
		{"domain get", func() error { _, e := domains.Get(ctx, "t", "d"); return e }, store.ErrCustomDomainRepositoryUnavailable},
		{"domain create", func() error { return domains.Create(ctx, &store.CustomDomain{}) }, store.ErrCustomDomainRepositoryUnavailable},
		{"host claim", func() error { return domains.PutHost(ctx, &store.HostBinding{}) }, store.ErrCustomDomainRepositoryUnavailable},
		{"attempt", func() error { _, e := domains.AdmitAttempt(ctx, "t", "d"); return e }, store.ErrCustomDomainRepositoryUnavailable},
		{"asset get", func() error { _, e := assets.Get(ctx, "a"); return e }, store.ErrTLSAssetRepositoryUnavailable},
		{"asset put", func() error { return assets.Put(ctx, &store.TLSAsset{}, 0) }, store.ErrTLSAssetRepositoryUnavailable},
		{"lease", func() error { _, e := assets.ClaimLease(ctx, "a", "worker", time.Minute); return e }, store.ErrTLSAssetRepositoryUnavailable},
	}
	for _, tt := range checks {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
}
