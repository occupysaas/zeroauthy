package seed

import (
	"context"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSeedDomainRPID(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte("tenants: [{name: acme, domains: [plain.example.net, {host: LOGIN.example.com., relying_party_identifier: example.com}]}]"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckManagementAPI("id.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.DomainRPIDs["login.example.com"] != "example.com" || !slices.Contains(tn.Domains, "plain.example.net") {
		t.Fatalf("alias RP IDs lost: %+v", tn)
	}
	strict := Options{RPIDPolicy: rpid.Policy{BaseDomain: "id.example.com", RestrictShared: true}}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t), strict); err == nil {
		t.Fatal("strict alias RP ID accepted")
	}
	// A later seeded tenant's host also restricts an earlier tenant's RP ID.
	f, err = Parse([]byte("tenants: [{name: first, domains: [{host: login.shared.example, relying_party_identifier: shared.example}]}, {name: second, domains: [other.shared.example]}]"))
	if err != nil {
		t.Fatal(err)
	}
	strict.RPIDPolicy.BaseDomain = "elsewhere.test"
	if err := Apply(ctx, memory.New(), f, fixedNow, testWrapper(t), strict); err == nil {
		t.Fatal("strict cross-tenant aliases accepted")
	}
	for _, raw := range []string{
		"{host: login.example.com, relying_party_identifier: unrelated.test}",
		"{host: login.example.co.uk, relying_party_identifier: co.uk}",
		"{host: login.example.com, typo: example.com}",
		"{relying_party_identifier: example.com}",
		"{host: login.example.com, relying_party_identifier: true}",
	} {
		if _, err := Parse([]byte("tenants: [{name: bad, domains: [" + raw + "]}]")); err == nil {
			t.Errorf("invalid alias accepted: %s", raw)
		}
	}
}

func TestSeedDomainRPIDPreservation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	apply := func(raw string, mode Mode) {
		t.Helper()
		f, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		f.Mode = mode
		if err := f.CheckManagementAPI("id.example.net"); err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
			t.Fatal(err)
		}
	}
	apply("tenants: [{name: acme, domains: [{host: login.example.com, relying_party_identifier: example.com}]}]", ModeApply)
	apply("tenants: [{name: acme, friendly_name: Updated}]", ModeApply)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.DomainRPIDs["login.example.com"] != "example.com" {
		t.Fatal("omitted domains cleared RP IDs")
	}
	apply("tenants: [{name: acme, domains: [{host: ignored.example.org, relying_party_identifier: example.org}]}]", ModeCreateOnly)
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if tn.DomainRPIDs["login.example.com"] != "example.com" || len(tn.DomainRPIDs) != 1 {
		t.Fatal("create-only changed RP IDs")
	}
	apply("tenants: [{name: acme, domains: [login.example.com]}]", ModeApply)
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if len(tn.DomainRPIDs) != 0 {
		t.Fatal("string domain did not clear override")
	}
}
