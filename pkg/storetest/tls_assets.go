package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testTLSAssetCopies(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	a := &store.TLSAsset{Key: "cert", Kind: store.TLSAssetCertificate, Ciphertext: []byte("sealed"), TenantID: "tenant", DomainID: "domain", Generation: 7, PublicData: store.TLSPublicData{Version: 1,
		DirectoryURL: "https://ca.example/directory", AccountURL: "https://ca.example/accounts/1", OrderURL: "https://ca.example/orders/2", Status: "valid",
		ChallengeType: "http-01", Identifier: "login.example", Token: "token", KeyAuthorization: "authorization", RecordName: "_acme-challenge.login.example", RecordValue: "dns-value", DNSRecordID: "owned-record-id",
		CertificateChainPEM: []byte("chain"), SANs: []string{"login.example"}, NotBefore: ts(-time.Hour), NotAfter: ts(time.Hour)}, ExpiresAt: ts(0)}
	want := a.Clone()
	want.Revision = 1
	mustNoErr(t, s.TLSAssets().Put(ctx, a, 0))
	mustEqual(t, a.Revision, int64(1))
	a.Ciphertext[0] = 'X'
	a.PublicData.SANs[0] = "evil.example"
	got, err := s.TLSAssets().Get(ctx, a.Key)
	mustNoErr(t, err)
	mustEqual(t, got, want)
	mustEqual(t, string(got.Ciphertext), "sealed")
	mustEqual(t, got.PublicData.SANs, []string{"login.example"})
	got.PublicData.CertificateChainPEM[0] = 'X'
	again, err := s.TLSAssets().Get(ctx, a.Key)
	mustNoErr(t, err)
	mustEqual(t, string(again.PublicData.CertificateChainPEM), "chain")
	mustErrIs(t, s.TLSAssets().Put(ctx, again, 0), store.ErrConflict)
	mustNoErr(t, s.TLSAssets().Put(ctx, again, 1))
	mustEqual(t, again.Revision, int64(2))
	mustErrIs(t, s.TLSAssets().Delete(ctx, a.Key, 1), store.ErrConflict)
	expired, err := s.TLSAssets().ListExpired(ctx, 1)
	mustNoErr(t, err)
	mustEqual(t, len(expired), 1)
	mustNoErr(t, s.TLSAssets().Delete(ctx, a.Key, 2))
	_, err = s.TLSAssets().Get(ctx, a.Key)
	mustErrIs(t, err, store.ErrNotFound)
}

func testTLSLeaseFence(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	lease, err := s.TLSAssets().ClaimLease(ctx, "resource", "first", time.Minute)
	mustNoErr(t, err)
	_, err = s.TLSAssets().ClaimLease(ctx, "resource", "second", time.Minute)
	mustErrIs(t, err, store.ErrConflict)
	wrong := *lease
	wrong.Owner = "wrong"
	mustErrIs(t, s.TLSAssets().CheckLease(ctx, wrong), store.ErrConflict)
	mustErrIs(t, s.TLSAssets().ReleaseLease(ctx, wrong), store.ErrConflict)
	renewed, err := s.TLSAssets().RenewLease(ctx, *lease, time.Minute)
	mustNoErr(t, err)
	mustEqual(t, renewed.Fence, lease.Fence)
	mustNoErr(t, s.TLSAssets().ReleaseLease(ctx, *renewed))
	successor, err := s.TLSAssets().ClaimLease(ctx, "resource", "second", time.Minute)
	mustNoErr(t, err)
	if successor.Fence <= lease.Fence {
		t.Fatal("lease fence did not increase after release")
	}
	mustErrIs(t, s.TLSAssets().ReleaseLease(ctx, *lease), store.ErrConflict)
	err = s.WithTx(ctx, func(tx store.Store) error {
		if e := tx.TLSAssets().CheckLease(ctx, *lease); e != nil {
			return e
		}
		return tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "stale-publication", Kind: store.TLSAssetCertificate}, 0)
	})
	mustErrIs(t, err, store.ErrConflict)
	_, err = s.TLSAssets().Get(ctx, "stale-publication")
	mustErrIs(t, err, store.ErrNotFound)
}
