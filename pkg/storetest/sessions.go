package storetest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newSession(tenantID, id, tokenHash string) *store.LoginSession {
	return &store.LoginSession{
		TenantID: tenantID, ID: id, TokenHash: tokenHash,
		UserID: "auth0|u1", Connection: "Database",
		CookieMode: "non-persistent", AuthenticatedAt: ts(0), ClientIDs: []string{"spa"},
		ExpiresAt: ts(7 * 24 * time.Hour), IdleExpiresAt: ts(3 * 24 * time.Hour), CreatedAt: ts(0),
		UpdatedAt: ts(0), LastInteractedAt: ts(0),
		InitialIP: "203.0.113.7", InitialUserAgent: "Mozilla/5.0 (initial)",
		LastIP: "203.0.113.7", LastUserAgent: "Mozilla/5.0 (initial)",
	}
}

func testSessions(t *testing.T, newStore Factory) {
	ctx := context.Background()
	t.Run("UserinfoClaims", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "claims", "claims-hash")
		want.UserinfoClaims = map[string]string{"a": `{"urn:one":true}`}
		mustNoErr(t, s.Sessions().Create(ctx, want))
		want.UserinfoClaims["a"] = "mutated"
		got, err := s.Sessions().Get(ctx, "ten_a", want.ID)
		mustNoErr(t, err)
		mustEqual(t, got.UserinfoClaims["a"], `{"urn:one":true}`)
		_, err = store.SetSessionClaims(ctx, s, "ten_a", want.ID, "b", `{"urn:two":true}`)
		mustNoErr(t, err)
		got, err = s.Sessions().Get(ctx, "ten_a", want.ID)
		mustNoErr(t, err)
		mustEqual(t, len(got.UserinfoClaims), 2)
		_, err = store.SetSessionClaims(ctx, s, "ten_b", want.ID, "a", `{}`)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = store.SetSessionClaims(ctx, s, "ten_a", want.ID, "a", `{"big":"`+strings.Repeat("x", 100000)+`"}`)
		if err == nil {
			t.Fatal("oversized claims accepted")
		}
	})

	t.Run("ClientOrganization", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "org-session", "org-hash")
		want.ClientOrganizations = map[string]string{"spa": "org_first"}
		mustNoErr(t, s.Sessions().Create(ctx, want))
		want.ClientOrganizations["spa"] = "mutated"
		got, err := s.Sessions().Get(ctx, "ten_a", want.ID)
		mustNoErr(t, err)
		mustEqual(t, got.ClientOrganizations, map[string]string{"spa": "org_first"})
		repo, ok := s.Sessions().(store.SessionOrganizationRecorder)
		if !ok {
			t.Fatal("missing recorder")
		}
		mustErrIs(t, repo.RecordClientOrganization(ctx, "ten_b", want.ID, "web", "org_other"), store.ErrNotFound)
		mustNoErr(t, repo.RecordClientOrganization(ctx, "ten_a", want.ID, "web", "org_second"))
		mustNoErr(t, repo.RecordClientOrganization(ctx, "ten_a", want.ID, "spa", ""))
		got, err = s.Sessions().Get(ctx, "ten_a", want.ID)
		mustNoErr(t, err)
		mustEqual(t, got.ClientOrganizations, map[string]string{"spa": "", "web": "org_second"})
		mustEqual(t, got.ClientIDs, []string{"spa", "web"})
		got.ClientOrganizations["web"] = "mutated"
		got, err = s.Sessions().Get(ctx, "ten_a", want.ID)
		mustNoErr(t, err)
		mustEqual(t, got.ClientOrganizations["web"], "org_second")
	})
	t.Run("GetForUpdate", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "locked", "locked-hash")
		mustNoErr(t, s.Sessions().Create(ctx, want))
		lock := func(st store.Store, tenantID string) (*store.LoginSession, error) {
			return st.Sessions().GetForUpdate(ctx, tenantID, want.ID)
		}
		got, err := lock(s, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = lock(s, "ten_b")
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			current, err := lock(tx, "ten_a")
			if err != nil {
				return err
			}
			mustEqual(t, current, want)
			return tx.Sessions().Touch(ctx, "ten_a", want.ID, ts(time.Hour), ts(2*time.Hour), "198.51.100.8", "current browser")
		}))
		want.LastInteractedAt, want.UpdatedAt = ts(time.Hour), ts(time.Hour)
		want.IdleExpiresAt, want.LastIP, want.LastUserAgent = ts(2*time.Hour), "198.51.100.8", "current browser"
		got, err = lock(s, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
			if _, err := lock(tx, "ten_a"); err != nil {
				return err
			}
			if err := tx.Sessions().Delete(ctx, "ten_a", want.ID); err != nil {
				return err
			}
			return store.ErrConflict
		}), store.ErrConflict)
		got, err = lock(s, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})

	t.Run("GetForUpdateSerializesInteraction", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "locked", "locked-hash")
		mustNoErr(t, s.Sessions().Create(ctx, want))
		started, finished := make(chan struct{}), make(chan error, 1)
		var premature bool
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.Sessions().GetForUpdate(ctx, "ten_a", want.ID); err != nil {
				return err
			}
			go func() {
				close(started)
				finished <- s.Sessions().Touch(ctx, "ten_a", want.ID, ts(time.Hour), ts(2*time.Hour), "198.51.100.8", "later browser")
			}()
			<-started
			select {
			case err := <-finished:
				premature = true
				finished <- err
			case <-time.After(200 * time.Millisecond):
			}
			return nil
		}))
		mustNoErr(t, <-finished)
		if premature {
			t.Fatal("browser interaction bypassed locked session")
		}
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			got, err := tx.Sessions().GetForUpdate(ctx, "ten_a", want.ID)
			if err != nil {
				return err
			}
			if !got.LastInteractedAt.Equal(ts(time.Hour)) || got.LastUserAgent != "later browser" {
				return fmt.Errorf("session lock returned stale interaction")
			}
			return nil
		}))
	})

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, want))
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash2")), store.ErrConflict)
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "hash1")), store.ErrConflict)

		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "hash1")
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(time.Hour), ts(4*24*time.Hour), "198.51.100.9", "Mozilla/5.0 (later)"))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web"))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web")) // idempotent
		want.ClientIDs = []string{"spa", "web"}
		want.IdleExpiresAt = ts(4 * 24 * time.Hour)
		want.UpdatedAt, want.LastInteractedAt = ts(time.Hour), ts(time.Hour)
		want.LastIP, want.LastUserAgent = "198.51.100.9", "Mozilla/5.0 (later)"
		got, _ = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, got, want)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_b", "s1", ts(0), ts(0), "", ""), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_b", "s1", "x"), store.ErrNotFound)

		mustNoErr(t, s.Sessions().Delete(ctx, "ten_a", "s1"))
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Sessions().Delete(ctx, "ten_a", "s1"), store.ErrNotFound)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(0), ts(0), "", ""), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "x"), store.ErrNotFound)
	})

	t.Run("GetAndListByUser", func(t *testing.T) {
		s := open(t, newStore)
		mk := func(id, user string, created time.Duration) {
			x := newSession("ten_a", id, "h-"+id)
			x.UserID, x.CreatedAt = user, ts(created)
			mustNoErr(t, s.Sessions().Create(ctx, x))
		}
		mk("a", "auth0|u1", time.Minute)
		mk("b", "auth0|u1", 3*time.Minute)
		mk("c", "auth0|u1", 3*time.Minute) // ties on CreatedAt: ID descending
		mk("d", "auth0|u1", 2*time.Minute)
		mk("e", "auth0|u2", 4*time.Minute)
		mustNoErr(t, s.Sessions().Create(ctx, func() *store.LoginSession {
			x := newSession("ten_b", "f", "h-f") // same user ID, other tenant
			x.CreatedAt = ts(5 * time.Minute)
			return x
		}()))

		got, err := s.Sessions().Get(ctx, "ten_a", "d")
		mustNoErr(t, err)
		want := newSession("ten_a", "d", "h-d")
		want.CreatedAt = ts(2 * time.Minute)
		mustEqual(t, got, want)
		_, err = s.Sessions().Get(ctx, "ten_b", "d")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Sessions().Get(ctx, "ten_a", "missing")
		mustErrIs(t, err, store.ErrNotFound)

		list, err := s.Sessions().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		var ids []string
		for _, x := range list {
			ids = append(ids, x.ID)
		}
		mustEqual(t, ids, []string{"c", "b", "d", "a"}) // newest first, ID descending on ties
		list, err = s.Sessions().ListByUser(ctx, "ten_a", "auth0|nobody")
		mustNoErr(t, err)
		mustEqual(t, len(list), 0)
		list, err = s.Sessions().ListByUser(ctx, "ten_b", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 1)

		// Copies, as everywhere.
		list, _ = s.Sessions().ListByUser(ctx, "ten_a", "auth0|u1")
		list[0].ClientIDs[0] = "mutated"
		again, _ := s.Sessions().Get(ctx, "ten_a", "c")
		mustEqual(t, again.ClientIDs, []string{"spa"})
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, in))
		in.ClientIDs[0] = "mutated"
		got, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		got.ClientIDs[0] = "mutated-too"
		again, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, again.ClientIDs, []string{"spa"})
	})

	t.Run("ConcurrentAddClient", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash1")))
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.Sessions().AddClient(ctx, "ten_a", "s1", fmt.Sprintf("c%d", i))
			}()
		}
		wg.Wait()
		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, len(got.ClientIDs), 21) // "spa" plus 20 distinct clients
		for i := range 20 {
			mustEqual(t, slices.Contains(got.ClientIDs, fmt.Sprintf("c%d", i)), true)
		}
	})

	t.Run("ConcurrentDeleteExpiredAndCreate", func(t *testing.T) {
		testSweepWhileCreating(t, newStore, sessionSweepTarget())
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		live := newSession("ten_a", "live", "h-live")
		absolute := newSession("ten_a", "abs", "h-abs")
		absolute.ExpiresAt = ts(time.Hour)
		idle := newSession("ten_a", "idle", "h-idle")
		idle.IdleExpiresAt = ts(time.Hour)
		edge := newSession("ten_a", "edge", "h-edge")
		edge.IdleExpiresAt = ts(2 * time.Hour) // exactly at the cutoff: expired
		other := newSession("ten_b", "other", "h-other")
		other.IdleExpiresAt = ts(time.Hour)
		for _, x := range []*store.LoginSession{live, absolute, idle, edge, other} {
			mustNoErr(t, s.Sessions().Create(ctx, x))
		}
		n, err := s.Sessions().DeleteExpired(ctx, ts(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 4)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h-live")
		mustNoErr(t, err)
		for _, k := range [][2]string{{"ten_a", "h-abs"}, {"ten_a", "h-idle"}, {"ten_a", "h-edge"}, {"ten_b", "h-other"}} {
			_, err = s.Sessions().GetByTokenHash(ctx, k[0], k[1])
			mustErrIs(t, err, store.ErrNotFound)
		}
	})

	t.Run("DeleteExpiredZeroTimes", func(t *testing.T) {
		// A zero ExpiresAt or IdleExpiresAt is "not after before": expired,
		// unlike refresh tokens, where zero means never.
		s := open(t, newStore)
		noAbs := newSession("ten_a", "noabs", "h-noabs")
		noAbs.ExpiresAt = time.Time{}
		noIdle := newSession("ten_a", "noidle", "h-noidle")
		noIdle.IdleExpiresAt = time.Time{}
		for _, x := range []*store.LoginSession{noAbs, noIdle, newSession("ten_a", "live", "h-live")} {
			mustNoErr(t, s.Sessions().Create(ctx, x))
		}
		n, err := s.Sessions().DeleteExpired(ctx, ts(0))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h-live")
		mustNoErr(t, err)
		for _, h := range []string{"h-noabs", "h-noidle"} {
			_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", h)
			mustErrIs(t, err, store.ErrNotFound)
		}
	})

	t.Run("DeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "h1"))) // auth0|u1
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "h2"))) // auth0|u1
		other := newSession("ten_a", "s3", "h3")
		other.UserID = "auth0|u2"
		mustNoErr(t, s.Sessions().Create(ctx, other))
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_b", "s4", "h4"))) // same user ID, other tenant
		n, err := s.Sessions().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h3")
		mustNoErr(t, err)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "h4")
		mustNoErr(t, err)
	})

	t.Run("SameHashAndIDAcrossTenants", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash1")))
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_b", "s1", "hash1")))
		a, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		b, _ := s.Sessions().GetByTokenHash(ctx, "ten_b", "hash1")
		mustEqual(t, a.TenantID, "ten_a")
		mustEqual(t, b.TenantID, "ten_b")
	})
}

func testSessionExpirySnapshots(t *testing.T, newStore Factory) {
	s := open(t, newStore)
	lister, ok := s.Sessions().(store.SessionExpiryLister)
	if !ok {
		t.Fatal("expiry snapshots unavailable")
	}
	for _, id := range []string{"a", "b", "live"} {
		session := newSession("ten_a", id, "token-"+id)
		session.ExpiresAt = ts(time.Hour)
		session.IdleExpiresAt = ts(time.Hour)
		if id != "live" {
			session.ExpiresAt = ts(0)
		}
		mustNoErr(t, s.Sessions().Create(t.Context(), session))
	}
	expired, err := lister.ListExpired(t.Context(), ts(0), 1)
	mustNoErr(t, err)
	if len(expired) != 1 || expired[0].ID != "a" {
		t.Fatal("expiry snapshot order or bound wrong")
	}
	expired[0].ClientIDs = append(expired[0].ClientIDs, "mutation")
	stored, err := s.Sessions().Get(t.Context(), "ten_a", "a")
	mustNoErr(t, err)
	if slices.Contains(stored.ClientIDs, "mutation") {
		t.Fatal("expiry snapshot aliases storage")
	}
	mustErrIs(t, func() error { _, err := lister.ListExpired(t.Context(), ts(0), 1001); return err }(), store.ErrInvalid)
	expired, err = lister.ListExpired(t.Context(), ts(0), 10)
	mustNoErr(t, err)
	if len(expired) != 2 {
		t.Fatal("expiry omitted due rows or included live row")
	}
}

// testSAMLSessionParticipants is Plan 37a: the SAML service providers a
// session answered are recorded for single logout, one entry per client.
func testSAMLSessionParticipants(t *testing.T, newStore Factory) {
	ctx := t.Context()
	s := open(t, newStore)
	rec, ok := s.Sessions().(store.SAMLSessionRecorder)
	if !ok {
		t.Fatal("sessions do not record SAML participants")
	}
	mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "sid", "h-sid")))
	mustNoErr(t, rec.RecordSAMLParticipant(ctx, "ten_a", "sid", store.SAMLParticipant{ClientID: "sp-a", NameID: "old", NameIDFormat: "urn:f", SessionIndex: "sid"}))
	mustNoErr(t, rec.RecordSAMLParticipant(ctx, "ten_a", "sid", store.SAMLParticipant{ClientID: "sp-b", NameID: "bob", SessionIndex: "sid"}))
	mustNoErr(t, rec.RecordSAMLParticipant(ctx, "ten_a", "sid", store.SAMLParticipant{ClientID: "sp-a", NameID: "alice", NameIDFormat: "urn:f", SessionIndex: "sid"}))
	got, err := s.Sessions().Get(ctx, "ten_a", "sid")
	mustNoErr(t, err)
	want := []store.SAMLParticipant{{ClientID: "sp-b", NameID: "bob", SessionIndex: "sid"}, {ClientID: "sp-a", NameID: "alice", NameIDFormat: "urn:f", SessionIndex: "sid"}}
	mustEqual(t, got.SAMLParticipants, want)
	if !slices.Contains(got.ClientIDs, "sp-a") || !slices.Contains(got.ClientIDs, "sp-b") {
		t.Fatalf("participants not added to the session's clients: %v", got.ClientIDs)
	}
	got.SAMLParticipants[0].NameID = "mutated"
	again, err := s.Sessions().Get(ctx, "ten_a", "sid")
	mustNoErr(t, err)
	mustEqual(t, again.SAMLParticipants, want)
	mustErrIs(t, rec.RecordSAMLParticipant(ctx, "ten_b", "sid", store.SAMLParticipant{ClientID: "x"}), store.ErrNotFound)
	// An upstream IdP entry is kept beside the SPs and adds no client.
	up := store.SAMLParticipant{ConnectionID: "con_up", NameID: "jdoe", SessionIndex: "idp-1"}
	mustNoErr(t, rec.RecordSAMLParticipant(ctx, "ten_a", "sid", up))
	got, err = s.Sessions().Get(ctx, "ten_a", "sid")
	mustNoErr(t, err)
	mustEqual(t, got.SAMLParticipants, append(want, up))
	if slices.Contains(got.ClientIDs, "") {
		t.Fatal("upstream entry added an empty client")
	}
}
