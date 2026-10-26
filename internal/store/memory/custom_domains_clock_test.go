package memory

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func clockStore(t *testing.T) (*Store, func(time.Duration)) {
	t.Helper()
	s := New()
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var ns atomic.Int64
	s.now = func() time.Time { return base.Add(time.Duration(ns.Load())) }
	set := func(d time.Duration) { ns.Store(int64(d)) }
	if err := s.Tenants().Create(context.Background(), &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	return s, set
}
func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error=%v want %v", got, want)
	}
}
func requireOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The domain cooldown and rolling tenant budget have independent boundaries;
// refused calls cannot consume either budget, including after a rollback.
func TestDomainAttemptStorageBoundaries(t *testing.T) {
	ctx := context.Background()
	s, set := clockStore(t)
	admit := func(id string, want time.Duration) {
		t.Helper()
		got, err := s.CustomDomains().AdmitAttempt(ctx, "tenant", id)
		requireOK(t, err)
		if got != want {
			t.Fatalf("%s retry=%v want %v", id, got, want)
		}
	}
	admit("a", 0)
	set(30*time.Second - time.Nanosecond)
	admit("a", time.Nanosecond)
	set(30 * time.Second)
	admit("a", 0)
	for i := 0; i < 18; i++ {
		admit(fmt.Sprint(i), 0)
	}
	admit("blocked", 30*time.Second)
	set(time.Minute - time.Nanosecond)
	admit("blocked", time.Nanosecond)
	set(time.Minute)
	admit("blocked", 0)
	// Only the first call at t=0 expires; the 19 calls at t=30 still count.
	admit("still-blocked", 30*time.Second)
	set(90 * time.Second)
	admit("still-blocked", 0)
	stop := errors.New("rollback")
	requireError(t, s.WithTx(ctx, func(tx store.Store) error {
		_, err := tx.CustomDomains().AdmitAttempt(ctx, "tenant", "rollback")
		if err != nil {
			return err
		}
		return stop
	}), stop)
	admit("rollback", 0)
}

func TestTLSLeaseExpiryAndTransactionFence(t *testing.T) {
	ctx := context.Background()
	s, set := clockStore(t)
	first, err := s.TLSAssets().ClaimLease(ctx, "cert", "worker-1", time.Minute)
	requireOK(t, err)
	set(time.Minute - time.Nanosecond)
	requireOK(t, s.TLSAssets().CheckLease(ctx, *first))
	set(time.Minute)
	requireError(t, s.TLSAssets().CheckLease(ctx, *first), store.ErrConflict)
	_, err = s.TLSAssets().RenewLease(ctx, *first, time.Minute)
	requireError(t, err, store.ErrConflict)
	requireError(t, s.TLSAssets().ReleaseLease(ctx, *first), store.ErrConflict)
	second, err := s.TLSAssets().ClaimLease(ctx, "cert", "worker-2", time.Minute)
	requireOK(t, err)
	if second.Fence <= first.Fence {
		t.Fatal("expired takeover reused fence")
	}
	// Check succeeds, but storage time reaches expiry before commit. Every write
	// in that transaction must roll back, including nested-savepoint publication.
	err = s.WithTx(ctx, func(tx store.Store) error {
		requireOK(t, tx.WithTx(ctx, func(inner store.Store) error { return inner.TLSAssets().CheckLease(ctx, *second) }))
		requireOK(t, tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "publication", Kind: store.TLSAssetCertificate}, 0))
		set(2 * time.Minute)
		return nil
	})
	requireError(t, err, store.ErrConflict)
	_, err = s.TLSAssets().Get(ctx, "publication")
	requireError(t, err, store.ErrNotFound)
	third, err := s.TLSAssets().ClaimLease(ctx, "cert", "worker-3", time.Minute)
	requireOK(t, err)
	if third.Fence <= second.Fence {
		t.Fatal("rollback restored a committed fence")
	}
	// A failed nested savepoint must not leak its expired lease guard outward.
	requireOK(t, s.WithTx(ctx, func(tx store.Store) error {
		stop := errors.New("savepoint rollback")
		requireError(t, tx.WithTx(ctx, func(inner store.Store) error { requireOK(t, inner.TLSAssets().CheckLease(ctx, *third)); return stop }), stop)
		set(3 * time.Minute)
		return tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "unrelated", Kind: store.TLSAssetAccount}, 0)
	}))
}

func TestTLSLeaseCheckSerializesTakeover(t *testing.T) {
	ctx := context.Background()
	s, set := clockStore(t)
	first, err := s.TLSAssets().ClaimLease(ctx, "cert", "first", time.Minute)
	requireOK(t, err)
	checked := make(chan struct{})
	resume := make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		committed <- s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.TLSAssets().CheckLease(ctx, *first); err != nil {
				return err
			}
			close(checked)
			<-resume
			return tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "publication", Kind: store.TLSAssetCertificate}, 0)
		})
	}()
	<-checked
	set(time.Minute)
	takeover := make(chan *store.TLSLease, 1)
	failed := make(chan error, 1)
	go func() {
		l, e := s.TLSAssets().ClaimLease(ctx, "cert", "second", time.Minute)
		if e != nil {
			failed <- e
			return
		}
		takeover <- l
	}()
	close(resume)
	requireError(t, <-committed, store.ErrConflict)
	select {
	case l := <-takeover:
		if l.Fence <= first.Fence {
			t.Fatal("fence reset")
		}
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("takeover blocked after rollback")
	}
	_, err = s.TLSAssets().Get(ctx, "publication")
	requireError(t, err, store.ErrNotFound)
}

func TestDomainAttemptTwoHandles(t *testing.T) {
	ctx := context.Background()
	s, set := clockStore(t)
	other := &Store{state: s.state}
	type result struct {
		retry time.Duration
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 40)
	for i := 0; i < 40; i++ {
		go func(i int) {
			<-start
			handle := s
			if i%2 == 1 {
				handle = other
			}
			retry, err := handle.CustomDomains().AdmitAttempt(ctx, "tenant", fmt.Sprint(i))
			results <- result{retry, err}
		}(i)
	}
	close(start)
	admitted := 0
	for i := 0; i < 40; i++ {
		r := <-results
		requireOK(t, r.err)
		if r.retry == 0 {
			admitted++
		} else if r.retry != time.Minute {
			t.Fatalf("tenant retry=%v", r.retry)
		}
	}
	if admitted != 20 {
		t.Fatalf("admitted=%d want20", admitted)
	}
	set(time.Minute)
	retry, err := other.CustomDomains().AdmitAttempt(ctx, "tenant", "same")
	requireOK(t, err)
	if retry != 0 {
		t.Fatalf("exact budget boundary refused: %v", retry)
	}
	retry, err = s.CustomDomains().AdmitAttempt(ctx, "tenant", "same")
	requireOK(t, err)
	if retry != 30*time.Second {
		t.Fatalf("independent handle missed cooldown: %v", retry)
	}
	set(90 * time.Second)
	retry, err = other.CustomDomains().AdmitAttempt(ctx, "tenant", "same")
	requireOK(t, err)
	if retry != 0 {
		t.Fatalf("exact domain boundary refused: %v", retry)
	}
}

func TestDomainExpiryStorageBoundaries(t *testing.T) {
	ctx := context.Background()
	s, set := clockStore(t)
	due := s.now().Add(time.Minute)
	d := &store.CustomDomain{TenantID: "tenant", ID: "domain", Domain: "login.customer.example", NextAttemptAt: &due}
	requireOK(t, s.CustomDomains().Create(ctx, d))
	a := &store.TLSAsset{Key: "cert", Kind: store.TLSAssetCertificate, ExpiresAt: due}
	requireOK(t, s.TLSAssets().Put(ctx, a, 0))
	set(time.Minute - time.Nanosecond)
	domains, err := s.CustomDomains().ListDue(ctx, 10)
	requireOK(t, err)
	if len(domains) != 0 {
		t.Fatal("domain due before equality")
	}
	assets, err := s.TLSAssets().ListExpired(ctx, 10)
	requireOK(t, err)
	if len(assets) != 0 {
		t.Fatal("asset expired before equality")
	}
	set(time.Minute)
	domains, err = s.CustomDomains().ListDue(ctx, 10)
	requireOK(t, err)
	if len(domains) != 1 {
		t.Fatal("domain not due at equality")
	}
	assets, err = s.TLSAssets().ListExpired(ctx, 10)
	requireOK(t, err)
	if len(assets) != 1 {
		t.Fatal("asset not expired at equality")
	}
}

func TestTLSLeaseRollbackPreservesFence(t *testing.T) {
	ctx := context.Background()
	s, _ := clockStore(t)
	l, err := s.TLSAssets().ClaimLease(ctx, "cert", "first", time.Minute)
	requireOK(t, err)
	stop := errors.New("rollback")
	requireError(t, s.WithTx(ctx, func(tx store.Store) error {
		requireOK(t, tx.TLSAssets().ReleaseLease(ctx, *l))
		next, e := tx.TLSAssets().ClaimLease(ctx, "cert", "second", time.Minute)
		requireOK(t, e)
		if next.Fence <= l.Fence {
			t.Fatal("transaction reused fence")
		}
		return stop
	}), stop)
	requireOK(t, s.TLSAssets().CheckLease(ctx, *l))
	requireOK(t, s.TLSAssets().ReleaseLease(ctx, *l))
	next, err := s.TLSAssets().ClaimLease(ctx, "cert", "third", time.Minute)
	requireOK(t, err)
	if next.Fence != l.Fence+1 {
		t.Fatalf("failed transaction changed committed fence history: %d", next.Fence)
	}
	requireError(t, s.TLSAssets().CheckLease(ctx, *l), store.ErrConflict)
}
