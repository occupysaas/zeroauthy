package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testADHub is Plan 38a (ad_hub.v1): one provisioning per connection with a
// tenant-unique ticket hash, connector sessions listed by liveness, purge,
// transactional rollback, and deletion with the connection and the tenant.
func testADHub(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("b")))
	for _, tid := range []string{"ten_a", "ten_b"} {
		mustNoErr(t, s.Connections().Create(ctx, &store.Connection{TenantID: tid, ID: "con_ad", Name: "corp", Strategy: store.StrategyAD}))
		mustNoErr(t, s.Connections().Create(ctx, &store.Connection{TenantID: tid, ID: "con_ad2", Name: "corp2", Strategy: store.StrategyAD}))
	}
	repo, err := store.ADHub(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	prov := func(tid, cid, hash string) *store.ADProvisioning {
		return &store.ADProvisioning{TenantID: tid, ConnectionID: cid, TicketHash: hash, TicketSealed: []byte{1, 2}, SigningKeySealed: []byte{3, 4}, CreatedAt: ts(0)}
	}
	mustNoErr(t, repo.CreateADProvisioning(ctx, prov("ten_a", "con_ad", "h1")))
	mustErrIs(t, repo.CreateADProvisioning(ctx, prov("ten_a", "con_ad", "h9")), store.ErrConflict)
	mustErrIs(t, repo.CreateADProvisioning(ctx, prov("ten_a", "con_ad2", "h1")), store.ErrConflict)
	mustNoErr(t, repo.CreateADProvisioning(ctx, prov("ten_b", "con_ad", "h1")))
	mustErrIs(t, repo.CreateADProvisioning(ctx, prov("ten_a", "", "h2")), store.ErrInvalid)
	got, err := repo.GetADProvisioning(ctx, "ten_a", "con_ad")
	mustNoErr(t, err)
	mustEqual(t, got.TicketHash, "h1")
	mustEqual(t, string(got.SigningKeySealed), string([]byte{3, 4}))
	mustEqual(t, got.CreatedAt.Equal(ts(0)), true)
	got, err = repo.FindADProvisioning(ctx, "ten_a", "h1")
	mustNoErr(t, err)
	mustEqual(t, got.ConnectionID, "con_ad")
	_, err = repo.FindADProvisioning(ctx, "ten_a", "h2")
	mustErrIs(t, err, store.ErrNotFound)
	_, err = repo.GetADProvisioning(ctx, "ten_a", "con_ad2")
	mustErrIs(t, err, store.ErrNotFound)

	sess := func(tid, cid, sid string, connected, seen time.Duration) *store.ADHubSession {
		return &store.ADHubSession{TenantID: tid, ConnectionID: cid, SessionID: sid, ReplicaID: "r1", ReplicaURL: "https://r1.internal:8443",
			CertThumbprint: "abc", AgentIP: "192.0.2.1", ConnectedAt: ts(connected * time.Second), LastSeenAt: ts(seen * time.Second)}
	}
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_a", "con_ad", "s1", 10, 20)))
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_a", "con_ad", "s2", 15, 30)))
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_a", "con_ad", "s3", 1, 2)))
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_b", "con_ad", "s1", 10, 20)))
	list, err := repo.ListADHubSessions(ctx, "ten_a", "con_ad", ts(5*time.Second))
	mustNoErr(t, err)
	mustEqual(t, len(list), 2)
	mustEqual(t, list[0].SessionID, "s2")
	mustEqual(t, list[1].SessionID, "s1")
	mustEqual(t, list[0].ReplicaURL, "https://r1.internal:8443")
	mustEqual(t, list[0].LastSeenAt.Equal(ts(30*time.Second)), true)
	// Put replaces by key (a heartbeat).
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_a", "con_ad", "s3", 1, 40)))
	list, err = repo.ListADHubSessions(ctx, "ten_a", "con_ad", ts(5*time.Second))
	mustNoErr(t, err)
	mustEqual(t, len(list), 3)
	mustNoErr(t, repo.DeleteADHubSession(ctx, "ten_a", "con_ad", "s3"))
	mustNoErr(t, repo.DeleteADHubSession(ctx, "ten_a", "con_ad", "missing"))
	list, err = repo.ListADHubSessions(ctx, "ten_a", "con_ad2", ts(0))
	mustNoErr(t, err)
	mustEqual(t, len(list), 0)

	// A rolled-back transaction leaves nothing behind.
	mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
		r, e := store.ADHub(ctx, tx)
		mustNoErr(t, e)
		mustNoErr(t, r.CreateADProvisioning(ctx, prov("ten_a", "con_ad2", "h3")))
		mustNoErr(t, r.PutADHubSession(ctx, sess("ten_a", "con_ad2", "s9", 50, 50)))
		return store.ErrConflict
	}), store.ErrConflict)
	_, err = repo.GetADProvisioning(ctx, "ten_a", "con_ad2")
	mustErrIs(t, err, store.ErrNotFound)

	n, err := repo.PurgeADHubSessions(ctx, ts(25*time.Second), 100)
	mustNoErr(t, err)
	mustEqual(t, n, 2) // ten_a s1 and ten_b s1
	list, err = repo.ListADHubSessions(ctx, "ten_a", "con_ad", ts(0))
	mustNoErr(t, err)
	mustEqual(t, len(list), 1)

	// Deleting the connection deletes its provisioning and sessions.
	mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con_ad"))
	_, err = repo.GetADProvisioning(ctx, "ten_a", "con_ad")
	mustErrIs(t, err, store.ErrNotFound)
	list, err = repo.ListADHubSessions(ctx, "ten_a", "con_ad", ts(0))
	mustNoErr(t, err)
	mustEqual(t, len(list), 0)
	_, err = repo.GetADProvisioning(ctx, "ten_b", "con_ad")
	mustNoErr(t, err)
	// Deleting the tenant deletes the rest.
	mustNoErr(t, repo.PutADHubSession(ctx, sess("ten_b", "con_ad", "s5", 60, 60)))
	mustNoErr(t, s.Tenants().Delete(ctx, "ten_b"))
	_, err = repo.FindADProvisioning(ctx, "ten_b", "h1")
	mustErrIs(t, err, store.ErrNotFound)
	list, err = repo.ListADHubSessions(ctx, "ten_b", "con_ad", ts(0))
	mustNoErr(t, err)
	mustEqual(t, len(list), 0)
}
