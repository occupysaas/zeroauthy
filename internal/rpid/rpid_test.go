package rpid

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func fixture(t *testing.T) (store.Store, *store.Tenant) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "ten_a", Name: "a", CanonicalHost: "a.example.test", DomainRPIDs: map[string]string{"alias2.example.org": "example.org"}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Tenants().Create(ctx, tn))
	must(st.Tenants().Create(ctx, &store.Tenant{ID: "ten_b", Name: "b", CanonicalHost: "b.example.test"}))
	for _, d := range []*store.CustomDomain{
		{TenantID: "ten_a", ID: "cd_plain", Domain: "plain.example.net", Status: "ready"},
		{TenantID: "ten_a", ID: "cd_rp", Domain: "login.example.com", Status: "ready", RelyingPartyIdentifier: "example.com"},
		{TenantID: "ten_a", ID: "cd_bad", Domain: "bad.example.com", Status: "ready", RelyingPartyIdentifier: "other.test"},
	} {
		must(st.CustomDomains().Create(ctx, d))
		must(st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: "ten_a", DomainID: d.ID, Kind: store.HostPublic, Active: true}))
	}
	for _, h := range []string{"alias.example.org", "alias2.example.org"} {
		must(st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: h, TenantID: "ten_a", Kind: store.HostOperator, Active: true}))
	}
	must(st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "b.other.example.com", TenantID: "ten_b", Kind: store.HostOperator, Active: true}))
	return st, tn
}

func TestRPIDFor(t *testing.T) {
	st, tn := fixture(t)
	var logs bytes.Buffer
	p := Policy{BaseDomain: "id.example.com", SystemHost: "system.example.test", Store: st, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	for _, c := range []struct {
		host, rpid string
		kind       Kind
		valid      bool
	}{
		{"a.example.test", "a.example.test", KindCanonical, true},
		{"plain.example.net", "plain.example.net", KindCustom, true},
		{"login.example.com", "example.com", KindCustom, true},
		{"alias.example.org", "alias.example.org", KindOperator, true},
		{"alias2.example.org", "example.org", KindOperator, true},
		{"bad.example.com", "other.test", KindCustom, false},
	} {
		r, err := p.For(context.Background(), tenant.Resolved{Tenant: tn, Host: c.host})
		if err != nil || r.RPID != c.rpid || r.Kind != c.kind || r.Valid != c.valid {
			t.Errorf("For(%s) = %+v, %v", c.host, r, err)
		}
	}
	if !strings.Contains(logs.String(), "bad.example.com") || !strings.Contains(logs.String(), "ten_a") {
		t.Errorf("invalid RP ID not logged: %s", logs.String())
	}
}

func TestRPIDHostWithPort(t *testing.T) {
	st, tn := fixture(t)
	p := Policy{Store: st}
	tn.CanonicalHost = "sdk.e2e.test:9543"
	r, err := p.For(context.Background(), tenant.Resolved{Tenant: tn, Host: "SDK.e2e.test.:9543"})
	if err != nil || r.RPID != "sdk.e2e.test" || r.Origin != "https://sdk.e2e.test:9543" || !r.Valid {
		t.Fatalf("ported host = %+v %v", r, err)
	}
	tn.CanonicalHost = "sdk.e2e.test"
	r, _ = p.For(context.Background(), tenant.Resolved{Tenant: tn, Host: "sdk.e2e.test"})
	if r.Origin != "https://sdk.e2e.test" {
		t.Fatalf("portless origin = %q", r.Origin)
	}
}

func TestRPIDValidateShared(t *testing.T) {
	st, _ := fixture(t)
	ctx := context.Background()
	lax := Policy{BaseDomain: "id.example.com", Store: st}
	if err := lax.Validate(ctx, "ten_a", "login.example.com", "example.com"); err != nil {
		t.Fatalf("default policy refused example.com: %v", err)
	}
	strict := lax
	strict.RestrictShared = true
	if err := strict.Validate(ctx, "ten_a", "login.example.com", "example.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("strict accepted an RP ID covering the base domain: %v", err)
	}
	other := Policy{BaseDomain: "id.elsewhere.test", Store: st, RestrictShared: true}
	if err := other.Validate(ctx, "ten_a", "login.example.com", "example.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("strict accepted an RP ID covering another tenant's host: %v", err)
	}
	for _, rp := range []string{"co.uk", "unrelated.test", strings.Repeat("a", 250) + ".example.com"} {
		if err := lax.Validate(ctx, "ten_a", "login.example.com", rp); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%q) = %v, want ErrInvalid", rp, err)
		}
	}
	if err := lax.Validate(ctx, "ten_a", "login.example.co.uk", "co.uk"); !errors.Is(err, ErrInvalid) {
		t.Error("public suffix accepted")
	}
}

func TestNativeOrigins(t *testing.T) {
	r := Result{RPID: "example.com", Origin: "https://login.example.com", Valid: true}
	c := &store.Client{WebOrigins: []string{"https://app.example.com", "https://evil.test"},
		Mobile: &store.ClientMobile{Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{strings.Repeat("AB:", 31) + "AB", "not-a-fingerprint"}}}}
	got := NativeOrigins(r, c)
	want := []string{"https://login.example.com", "https://app.example.com", "android:apk-key-hash:q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"}
	if !slices.Equal(got, want) {
		t.Fatalf("NativeOrigins = %v, want %v", got, want)
	}
	if got := NativeOrigins(r, nil); !slices.Equal(got, []string{"https://login.example.com"}) {
		t.Fatalf("nil client = %v", got)
	}
}

func TestNativeOriginsRejectNonOrigins(t *testing.T) {
	r := Result{RPID: "example.com", Origin: "https://login.example.com", Valid: true}
	c := &store.Client{WebOrigins: []string{
		"https://app.example.com:9543", "https://app.example.com/", "https://user@app.example.com",
		"https://app.example.com?x=1", "https://app.example.com#section", "https://app.example.com/path",
		"https://app.example.com:", "https://app.example.com:99999", "https://app.example.com:garbage",
		"http://app.example.com", "https://evil.test", "https://APP.example.com", "https://app.example.com.",
	}}
	want := []string{r.Origin, "https://app.example.com:9543"}
	if got := NativeOrigins(r, c); !slices.Equal(got, want) {
		t.Fatalf("non-origin accepted: %v, want %v", got, want)
	}
}

func TestRPIDForInactiveAndStrict(t *testing.T) {
	st, tn := fixture(t)
	ctx := context.Background()
	b, _ := st.CustomDomains().GetHost(ctx, "login.example.com")
	b.Active = false
	if err := st.CustomDomains().PutHost(ctx, b); err != nil {
		t.Fatal(err)
	}
	p := Policy{Store: st}
	r, err := p.For(ctx, tenant.Resolved{Tenant: tn, Host: b.Host})
	if err != nil || r.Valid {
		t.Fatalf("inactive custom binding = %+v %v", r, err)
	}
	// Explicit self RP IDs also obey strict sharing policy.
	d, _ := st.CustomDomains().Get(ctx, tn.ID, "cd_plain")
	d.RelyingPartyIdentifier = d.Domain
	if err := st.CustomDomains().Update(ctx, d, d.Revision); err != nil {
		t.Fatal(err)
	}
	if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "child." + d.Domain, TenantID: "ten_b", Kind: store.HostOperator, Active: true}); err != nil {
		t.Fatal(err)
	}
	p.RestrictShared = true
	var logs bytes.Buffer
	p.Log = slog.New(slog.NewTextHandler(&logs, nil))
	r, err = p.For(ctx, tenant.Resolved{Tenant: tn, Host: d.Domain})
	if err != nil || r.Valid || strings.Count(logs.String(), "level=WARN") != 1 {
		t.Fatalf("strict self RP ID = %+v %v logs=%s", r, err, logs.String())
	}
}

type withoutWebAuthn struct{ store.Store }

func (withoutWebAuthn) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

func TestRPIDValidateSharedUnavailable(t *testing.T) {
	st, _ := fixture(t)
	p := Policy{Store: withoutWebAuthn{st}, RestrictShared: true}
	if err := p.Validate(context.Background(), "ten_a", "login.example.com", "example.com"); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("unavailable host registry allowed strict RP ID: %v", err)
	}
}
