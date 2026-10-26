package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func domainFixture(tenant, id string) *store.CustomDomain {
	at := ts(0)
	return &store.CustomDomain{
		TenantID: tenant, ID: id, Domain: id + ".customer.example", Type: "auth0_managed_certs", Source: store.OriginAPI, OriginHost: id + ".origin.example",
		Generation: 1, Status: "pending", TLSPolicy: "recommended", CustomClientIPHeader: "x-forwarded-for", RelyingPartyIdentifier: "customer.example",
		DomainMetadata: map[string]string{"team": "security"}, VerificationMethod: "txt", ProofRecordName: "_zeroauthy." + id + ".customer.example", ProofRecordValue: "proof-value", ProofStatus: "pending",
		ProofToken: []byte("proof"), ProofCreatedAt: ts(-time.Hour), ProofVerifiedAt: &at, LastProofCheckAt: &at, ProofFailureSince: &at, Lifecycle: "proof_pending", NextAttemptAt: &at,
		AttemptCount: 3, LastFailure: "retry", ProxyKeyHash: []byte("hash"), ActiveCertificateKey: "cert/" + id, CreatedAt: ts(-2 * time.Hour), UpdatedAt: ts(-time.Minute),
	}
}

// Catch global uniqueness bypasses, cross-owner mutations, and tenant writers
// activating API claims before proof or stealing private origins.
func testCustomDomainClaims(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	for _, n := range []string{"acme", "globex"} {
		mustNoErr(t, s.Tenants().Create(ctx, newTenant(n)))
	}
	results := parallel(2, func(i int) error {
		return s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: []string{"BÜCHER.customer.example.", "xn--bcher-kva.customer.example"}[i], TenantID: []string{"ten_acme", "ten_globex"}[i], DomainID: "custom", Generation: 1, Kind: store.HostPublic})
	})
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else {
			mustErrIs(t, err, store.ErrConflict)
		}
	}
	mustEqual(t, winners, 1)
	h, err := s.CustomDomains().GetHost(ctx, "XN--BCHER-KVA.customer.example.")
	mustNoErr(t, err)
	other := "ten_acme"
	if h.TenantID == other {
		other = "ten_globex"
	}
	mustErrIs(t, s.CustomDomains().DeleteHost(ctx, h.Host, other, h.DomainID), store.ErrConflict)
	stolen := *h
	stolen.DomainID = "different"
	mustErrIs(t, s.CustomDomains().PutHost(ctx, &stolen), store.ErrConflict)
	h.Active = true
	mustNoErr(t, s.CustomDomains().PutHost(ctx, h))
	h.Active = false
	got, err := s.CustomDomains().GetHost(ctx, h.Host)
	mustNoErr(t, err)
	mustEqual(t, got.Active, true)
	mustNoErr(t, s.CustomDomains().DeleteHost(ctx, h.Host, h.TenantID, h.DomainID))
	mustNoErr(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "pending.customer.example", TenantID: "ten_acme", DomainID: "pending", Generation: 1, Kind: store.HostPublic}))
	mustNoErr(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "private.origin.example", TenantID: "ten_acme", DomainID: "pending", Generation: 1, Kind: store.HostOrigin, Active: true}))
	for _, host := range []string{"pending.customer.example", "private.origin.example"} {
		tn, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		tn.Domains = append(tn.Domains, host)
		mustErrIs(t, s.Tenants().Update(ctx, tn), store.ErrConflict)
		fresh := newTenant("steal")
		fresh.Domains = []string{host}
		mustErrIs(t, s.Tenants().Create(ctx, fresh), store.ErrConflict)
	}
	tn, err := s.Tenants().Get(ctx, "ten_acme")
	mustNoErr(t, err)
	tn.CanonicalHost = "canonical.customer.example"
	mustNoErr(t, s.Tenants().Update(ctx, tn))
	canonical, err := s.CustomDomains().GetHost(ctx, tn.CanonicalHost)
	mustNoErr(t, err)
	mustEqual(t, canonical.Kind, store.HostCanonical)
	tn.CanonicalHost = "replacement.customer.example"
	mustErrIs(t, s.Tenants().Update(ctx, tn), store.ErrConflict)
	tn, err = s.Tenants().Get(ctx, "ten_acme")
	mustNoErr(t, err)
	mustNoErr(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "active.customer.example", TenantID: tn.ID, DomainID: "active", Generation: 1, Kind: store.HostPublic, Active: true}))
	tn.Domains = []string{"replacement-operator.example"}
	mustNoErr(t, s.Tenants().Update(ctx, tn))
	preserved, err := s.Tenants().Get(ctx, tn.ID)
	mustNoErr(t, err)
	mustEqual(t, preserved.Domains, []string{"replacement-operator.example", "canonical.customer.example", "active.customer.example"})
	_, err = s.Tenants().GetByDomain(ctx, "pending.customer.example")
	mustErrIs(t, err, store.ErrNotFound)
	_, err = s.Tenants().GetByDomain(ctx, "private.origin.example")
	mustErrIs(t, err, store.ErrNotFound)
	_, err = s.Tenants().GetByDomain(ctx, "active.customer.example")
	mustNoErr(t, err)
	_, err = s.CustomDomains().GetHost(ctx, "acme.example.test")
	mustErrIs(t, err, store.ErrNotFound)
	mustErrIs(t, s.CustomDomains().DeleteHost(ctx, "canonical.customer.example", tn.ID, ""), store.ErrConflict)

	contender := newTenant("contender")
	contender.Domains = []string{"RACE.customer.example."}
	races := parallel(2, func(i int) error {
		if i == 0 {
			return s.Tenants().Create(ctx, contender)
		}
		return s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "race.customer.example", TenantID: "ten_acme", DomainID: "race", Kind: store.HostPublic})
	})
	wins := 0
	for _, e := range races {
		if e == nil {
			wins++
		} else {
			mustErrIs(t, e, store.ErrConflict)
		}
	}
	mustEqual(t, wins, 1)

	local := newTenant("local")
	local.Domains = []string{"LOCALHOST:8080"}
	mustNoErr(t, s.Tenants().Create(ctx, local))
	_, err = s.CustomDomains().GetHost(ctx, "localhost:8080")
	mustNoErr(t, err)
}

// Catch lost CAS updates, mutable aliases and nondeterministic list ordering.
func testCustomDomainCAS(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
	d := domainFixture("ten_acme", "b")
	mustNoErr(t, s.CustomDomains().Create(ctx, d))
	mustEqual(t, d.Revision, int64(1))
	mustErrIs(t, s.CustomDomains().Create(ctx, d), store.ErrConflict)
	d.DomainMetadata["team"] = "mutated"
	d.ProofToken[0] = 'X'
	*d.NextAttemptAt = ts(time.Hour)
	got, err := s.CustomDomains().Get(ctx, d.TenantID, d.ID)
	mustNoErr(t, err)
	want := domainFixture("ten_acme", "b")
	want.Revision = 1
	mustEqual(t, got, want)
	mustEqual(t, got.DomainMetadata["team"], "security")
	mustEqual(t, string(got.ProofToken), "proof")
	mustEqual(t, *got.NextAttemptAt, ts(0))
	revision := got.Revision
	results := parallel(2, func(i int) error {
		c := got.Clone()
		c.LastFailure = fmt.Sprint(i)
		return s.CustomDomains().Update(ctx, c, revision)
	})
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else {
			mustErrIs(t, err, store.ErrConflict)
		}
	}
	mustEqual(t, winners, 1)
	mustErrIs(t, s.CustomDomains().Delete(ctx, d.TenantID, d.ID, revision), store.ErrConflict)
	got, err = s.CustomDomains().Get(ctx, d.TenantID, d.ID)
	mustNoErr(t, err)
	mustEqual(t, got.Revision, revision+1)
	got.Generation++
	mustNoErr(t, s.CustomDomains().Update(ctx, got, got.Revision))
	updated, err := s.CustomDomains().Get(ctx, got.TenantID, got.ID)
	mustNoErr(t, err)
	mustEqual(t, updated, got)
	unicode := domainFixture(d.TenantID, "unicode")
	unicode.Domain = "BÜCHER.customer.example."
	mustNoErr(t, s.CustomDomains().Create(ctx, unicode))
	unicode.Status = "ready"
	mustNoErr(t, s.CustomDomains().Update(ctx, unicode, unicode.Revision))
	normalized, err := s.CustomDomains().Get(ctx, unicode.TenantID, unicode.ID)
	mustNoErr(t, err)
	mustEqual(t, normalized.Domain, "xn--bcher-kva.customer.example")
	mustNoErr(t, s.CustomDomains().Delete(ctx, unicode.TenantID, unicode.ID, unicode.Revision))

	a := domainFixture(d.TenantID, "a")
	mustNoErr(t, s.CustomDomains().Create(ctx, a))
	list, err := s.CustomDomains().List(ctx, d.TenantID)
	mustNoErr(t, err)
	mustEqual(t, []string{list[0].ID, list[1].ID}, []string{"a", "b"})
	due, err := s.CustomDomains().ListDue(ctx, 1)
	mustNoErr(t, err)
	mustEqual(t, len(due), 1)
	mustEqual(t, due[0].ID, "a")
	list[0].ProxyKeyHash[0] = 'X'
	again, err := s.CustomDomains().Get(ctx, a.TenantID, a.ID)
	mustNoErr(t, err)
	mustEqual(t, string(again.ProxyKeyHash), "hash")
	mustNoErr(t, s.CustomDomains().Delete(ctx, d.TenantID, d.ID, got.Revision))
	_, err = s.CustomDomains().Get(ctx, d.TenantID, d.ID)
	mustErrIs(t, err, store.ErrNotFound)
}

func testCustomDomainDefaultRollback(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
	d := domainFixture("ten_acme", "custom")
	mustNoErr(t, s.CustomDomains().Create(ctx, d))
	stop := errors.New("rollback")
	err := s.WithTx(ctx, func(tx store.Store) error {
		d.Status = "ready"
		mustNoErr(t, tx.CustomDomains().Update(ctx, d, d.Revision))
		mustNoErr(t, tx.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, Kind: store.HostPublic, Active: true}))
		mustNoErr(t, tx.CustomDomains().SetDefault(ctx, d.TenantID, d.ID))
		tn, e := tx.Tenants().Get(ctx, d.TenantID)
		mustNoErr(t, e)
		tn.Domains = append(tn.Domains, d.Domain)
		mustNoErr(t, tx.Tenants().Update(ctx, tn))
		return stop
	})
	mustErrIs(t, err, stop)
	got, err := s.CustomDomains().Get(ctx, d.TenantID, d.ID)
	mustNoErr(t, err)
	mustEqual(t, got.Status, "pending")
	mustEqual(t, got.Revision, int64(1))
	def, err := s.CustomDomains().GetDefault(ctx, d.TenantID)
	mustNoErr(t, err)
	mustEqual(t, def, "")
	_, err = s.CustomDomains().GetHost(ctx, d.Domain)
	mustErrIs(t, err, store.ErrNotFound)
	tn, err := s.Tenants().Get(ctx, d.TenantID)
	mustNoErr(t, err)
	mustEqual(t, tn.Domains, []string{"acme.example.test"})
	// Either ordering must leave no default pointing at a deleted domain.
	races := parallel(2, func(i int) error {
		if i == 0 {
			return s.CustomDomains().SetDefault(ctx, d.TenantID, d.ID)
		}
		return s.CustomDomains().Delete(ctx, d.TenantID, d.ID, got.Revision)
	})
	mustNoErr(t, races[1])
	if races[0] != nil {
		mustErrIs(t, races[0], store.ErrNotFound)
	}
	def, err = s.CustomDomains().GetDefault(ctx, d.TenantID)
	mustNoErr(t, err)
	mustEqual(t, def, "")

}

func testCustomDomainCascade(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
	d := domainFixture("ten_acme", "custom")
	mustNoErr(t, s.CustomDomains().Create(ctx, d))
	mustNoErr(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: d.TenantID, DomainID: d.ID, Kind: store.HostPublic, Active: true}))
	mustNoErr(t, s.CustomDomains().SetDefault(ctx, d.TenantID, d.ID))
	for _, a := range []*store.TLSAsset{{Key: "leaf", TenantID: d.TenantID, DomainID: d.ID, Kind: store.TLSAssetCertificate}, {Key: "challenge", TenantID: d.TenantID, DomainID: d.ID, Kind: store.TLSAssetChallenge}, {Key: "account", Kind: store.TLSAssetAccount}, {Key: "wildcard", Kind: store.TLSAssetCertificate}} {
		mustNoErr(t, s.TLSAssets().Put(ctx, a, 0))
	}
	mustNoErr(t, s.CustomDomains().Delete(ctx, d.TenantID, d.ID, d.Revision))
	for _, key := range []string{"leaf", "challenge"} {
		_, err := s.TLSAssets().Get(ctx, key)
		mustErrIs(t, err, store.ErrNotFound)
	}
	for _, key := range []string{"account", "wildcard"} {
		_, err := s.TLSAssets().Get(ctx, key)
		mustNoErr(t, err)
	}
	_, err := s.CustomDomains().GetHost(ctx, d.Domain)
	mustErrIs(t, err, store.ErrNotFound)
	def, err := s.CustomDomains().GetDefault(ctx, d.TenantID)
	mustNoErr(t, err)
	mustEqual(t, def, "")
	d = domainFixture("ten_acme", "second")
	mustNoErr(t, s.CustomDomains().Create(ctx, d))
	mustNoErr(t, s.Tenants().Delete(ctx, d.TenantID))
	_, err = s.CustomDomains().Get(ctx, d.TenantID, d.ID)
	mustErrIs(t, err, store.ErrNotFound)
	_, err = s.CustomDomains().GetHost(ctx, "acme.example.test")
	mustErrIs(t, err, store.ErrNotFound)
	for _, key := range []string{"account", "wildcard"} {
		_, err := s.TLSAssets().Get(ctx, key)
		mustNoErr(t, err)
	}
}

// Catch per-process budgets, off-by-one tenant limits, and partial admission
// updates on refusal. Driver-specific clock tests pin exact expiry boundaries.
func testCustomDomainAttemptLimits(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	for _, n := range []string{"acme", "globex"} {
		mustNoErr(t, s.Tenants().Create(ctx, newTenant(n)))
	}
	retry, err := s.CustomDomains().AdmitAttempt(ctx, "ten_acme", "same")
	mustNoErr(t, err)
	mustEqual(t, retry, time.Duration(0))
	retry, err = s.CustomDomains().AdmitAttempt(ctx, "ten_acme", "same")
	mustNoErr(t, err)
	if retry <= 0 || retry > 30*time.Second {
		t.Fatalf("domain cooldown=%v", retry)
	}
	for i := 0; i < 19; i++ {
		retry, err = s.CustomDomains().AdmitAttempt(ctx, "ten_acme", fmt.Sprint(i))
		mustNoErr(t, err)
		mustEqual(t, retry, time.Duration(0))
	}
	retry, err = s.CustomDomains().AdmitAttempt(ctx, "ten_acme", "over-limit")
	mustNoErr(t, err)
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("tenant cooldown=%v", retry)
	}
	retry, err = s.CustomDomains().AdmitAttempt(ctx, "ten_globex", "same")
	mustNoErr(t, err)
	mustEqual(t, retry, time.Duration(0))
}
