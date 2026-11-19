package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func familyToken(id, family string, rotating bool) *store.RefreshToken {
	rt := newRefreshToken("ten_a", id, "hash-"+id, family)
	rt.Rotating = rotating
	return rt
}

func testRefreshTokensII(t *testing.T, newStore Factory) {
	t.Run("ConversionFreshFamily", func(t *testing.T) { testConversionFreshFamily(t, newStore) })
	ctx := context.Background()
	t.Run("StrictLeeway", func(t *testing.T) {
		repo := open(t, newStore).RefreshTokens()
		at := ts(time.Minute)
		mustNoErr(t, repo.Create(ctx, familyToken("t0", "family", true)))
		rotate := func(from, to string) error {
			return repo.Rotate(ctx, "ten_a", from, familyToken(to, "family", true), at, time.Minute)
		}
		mustNoErr(t, rotate("t0", "t1"))
		mustNoErr(t, rotate("t1", "t2"))
		mustNoErr(t, rotate("t1", "a-sibling"))
		mustNoErr(t, rotate("t2", "z-child"))
		// Multiple live siblings have identical creation and rotation timestamps.
		mustNoErr(t, rotate("t2", "a-child"))
		mustErrIs(t, rotate("t0", "invalid"), store.ErrAlreadyUsed)
		for _, id := range []string{"t0", "t1", "t2", "a-sibling", "z-child", "a-child"} {
			token, err := repo.Get(ctx, "ten_a", id)
			mustNoErr(t, err)
			mustEqual(t, token.RevokedAt != nil, true)
		}
	})
	for _, rotating := range []bool{false, true} {
		name := "ConvertNonRotating"
		if rotating {
			name = "ConvertRotating"
		}
		t.Run(name, func(t *testing.T) {
			repo := open(t, newStore).RefreshTokens()
			for _, id := range []string{"a", "b", "c", "other-aud", "other-client", "other-user", "other-tenant", "online"} {
				rt := familyToken(id, "f"+id, rotating)
				switch id {
				case "other-aud":
					rt.Audience = "https://other.test"
				case "other-client":
					rt.ClientID = "other"
				case "other-user":
					rt.UserID = "u2"
				case "other-tenant":
					rt.TenantID = "ten_b"
				case "online":
					rt.Access = "online"
					rt.Rotating = false
				}
				rt.DPoPJKT = "key"
				mustNoErr(t, repo.Create(ctx, rt))
			}
			next := familyToken("next", "new", !rotating)
			convert := func() error {
				if rotating {
					return repo.ConvertRotating(ctx, "ten_a", "a", next, ts(time.Minute), time.Minute)
				}
				return repo.ConvertNonRotating(ctx, "ten_a", "a", next)
			}
			mustErrIs(t, convert(), store.ErrConflict) // bound family cannot become unbound
			next.DPoPJKT = "key"
			next.ClientID = "other"
			mustErrIs(t, convert(), store.ErrConflict)
			next.ClientID = "spa"
			mustNoErr(t, convert())
			got, err := repo.Get(ctx, "ten_a", "next")
			mustNoErr(t, err)
			mustEqual(t, got.DPoPJKT, "key")
			mustEqual(t, got.Rotating, !rotating)
			mustEqual(t, got.RevokedAt == nil, true)
			for _, id := range []string{"a", "b", "c"} {
				old, err := repo.Get(ctx, "ten_a", id)
				if rotating {
					mustNoErr(t, err)
					mustEqual(t, old.RevokedAt, new(ts(time.Minute)))
				} else {
					mustErrIs(t, err, store.ErrNotFound)
				}
			}
			for _, id := range []string{"other-aud", "other-client", "other-user", "other-tenant", "online"} {
				tenant := "ten_a"
				if id == "other-tenant" {
					tenant = "ten_b"
				}
				got, err := repo.Get(ctx, tenant, id)
				mustNoErr(t, err)
				mustEqual(t, got.RevokedAt == nil, true)
			}
		})
	}
	for _, tc := range []struct {
		name, presented string
		elapsed         time.Duration
		accepted        bool
	}{
		{"previous", "t1", time.Second, true}, {"older", "t0", time.Second, false}, {"outside", "t1", time.Minute, false},
	} {
		t.Run("ConvertRotatingLeeway/"+tc.name, func(t *testing.T) {
			repo := open(t, newStore).RefreshTokens()
			mustNoErr(t, repo.Create(ctx, familyToken("other", "other", true)))
			mustNoErr(t, repo.Create(ctx, familyToken("t0", "f", true)))
			at := ts(time.Minute)
			mustNoErr(t, repo.Rotate(ctx, "ten_a", "t0", familyToken("t1", "f", true), at, time.Minute))
			mustNoErr(t, repo.Rotate(ctx, "ten_a", "t1", familyToken("t2", "f", true), at, time.Minute))
			err := repo.ConvertRotating(ctx, "ten_a", tc.presented, familyToken("next", "new", false), at.Add(tc.elapsed), time.Minute)
			if tc.accepted {
				mustNoErr(t, err)
			} else {
				mustErrIs(t, err, store.ErrAlreadyUsed)
				_, err = repo.Get(ctx, "ten_a", "next")
				mustErrIs(t, err, store.ErrNotFound)
			}
			rt, err := repo.Get(ctx, "ten_a", "t2")
			mustNoErr(t, err)
			mustEqual(t, rt.RevokedAt != nil, true)
			rt, err = repo.Get(ctx, "ten_a", "other")
			mustNoErr(t, err)
			mustEqual(t, rt.RevokedAt != nil, tc.accepted)
		})
	}
	t.Run("ConvertOneWinner", func(t *testing.T) {
		repo := open(t, newStore).RefreshTokens()
		mustNoErr(t, repo.Create(ctx, familyToken("start", "f", false)))
		errs := parallel(8, func(i int) error {
			id := fmt.Sprint(i)
			return repo.ConvertNonRotating(ctx, "ten_a", "start", familyToken(id, id, true))
		})
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else {
				mustErrIs(t, err, store.ErrNotFound)
			}
		}
		mustEqual(t, wins, 1)
	})
	t.Run("ListByUserPageAndRevocation", func(t *testing.T) {
		repo := open(t, newStore).RefreshTokens()
		for _, id := range []string{"c", "b", "a", "other-client", "other-user", "online", "other-tenant"} {
			rt := familyToken(id, id, false)
			switch id {
			case "c":
				rt.Audience = "https://other.test"
			case "other-client":
				rt.ClientID = "other"
				rt.SessionID = "s2"
			case "other-user":
				rt.UserID = "u2"
				rt.SessionID = "s3"
			case "other-tenant":
				rt.TenantID = "ten_b"
			case "online":
				rt.Access = "online"
				rt.SessionID = "s2"
			}
			mustNoErr(t, repo.Create(ctx, rt))
		}
		list, next, err := repo.ListByUserPage(ctx, "ten_a", "auth0|u1", "spa", "", 2)
		mustNoErr(t, err)
		mustEqual(t, len(list), 2)
		mustEqual(t, list[0].ID, "a")
		mustEqual(t, list[1].ID, "b")
		mustEqual(t, next, "b")
		list, next, err = repo.ListByUserPage(ctx, "ten_a", "auth0|u1", "spa", next, 2)
		mustNoErr(t, err)
		mustEqual(t, len(list), 1)
		mustEqual(t, list[0].ID, "c")
		mustEqual(t, next, "")
		n, err := repo.RevokeBySession(ctx, "ten_a", "s2", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		n, err = repo.RevokeByUserClient(ctx, "ten_a", "auth0|u1", "spa", "https://api.test", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		n, err = repo.RevokeByUserClient(ctx, "ten_a", "auth0|u1", "spa", "", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		list, _, err = repo.ListByUserPage(ctx, "ten_a", "auth0|u1", "", "", 2)
		mustNoErr(t, err)
		mustEqual(t, len(list), 0)
		for _, tc := range []struct{ tenant, id string }{{"ten_a", "other-user"}, {"ten_b", "other-tenant"}} {
			rt, err := repo.Get(ctx, tc.tenant, tc.id)
			mustNoErr(t, err)
			mustEqual(t, rt.RevokedAt == nil, true)
		}
	})
	t.Run("RefreshTokenMetadataAndExchange", func(t *testing.T) {
		repo := open(t, newStore).RefreshTokens()
		rt := familyToken("rt", "f", true)
		rt.Metadata = map[string]string{"old": "value"}
		rt.Device = &store.RefreshTokenDevice{InitialIP: "192.0.2.1", InitialUserAgent: "original"}
		rt.DPoPJKT = "key"
		mustNoErr(t, repo.Create(ctx, rt))
		rt.Metadata["old"] = "mutated"
		rt.Device.InitialIP = "mutated"
		got, err := repo.Get(ctx, "ten_a", "rt")
		mustNoErr(t, err)
		mustEqual(t, got.Metadata["old"], "value")
		md := map[string]string{"new": "value"}
		got, err = repo.UpdateMetadata(ctx, "ten_a", "rt", md)
		mustNoErr(t, err)
		mustEqual(t, got.Metadata, md)
		md["new"] = "changed"
		got.Metadata["new"] = "changed"
		at := ts(time.Minute)
		mustNoErr(t, repo.RecordExchange(ctx, "ten_a", "rt", "192.0.2.2", "updated", at))
		got, err = repo.Get(ctx, "ten_a", "rt")
		mustNoErr(t, err)
		mustEqual(t, got.Metadata, map[string]string{"new": "value"})
		mustEqual(t, got.Device, &store.RefreshTokenDevice{InitialIP: "192.0.2.1", InitialUserAgent: "original", LastIP: "192.0.2.2", LastUserAgent: "updated"})
		mustEqual(t, got.LastExchangedAt, &at)
		*got.LastExchangedAt = ts(time.Hour)
		got.Device.InitialIP = "changed"
		got, err = repo.UpdateMetadata(ctx, "ten_a", "rt", nil)
		mustNoErr(t, err)
		mustEqual(t, len(got.Metadata), 0)
		mustEqual(t, got.LastExchangedAt.Equal(at), true)
		mustEqual(t, got.Device.InitialIP, "192.0.2.1")
		next := familyToken("next", "f", true)
		mustErrIs(t, repo.Rotate(ctx, "ten_a", "rt", next, at, time.Minute), store.ErrConflict)
		next.DPoPJKT = "key"
		mustNoErr(t, repo.Rotate(ctx, "ten_a", "rt", next, at, time.Minute))
		got, err = repo.Get(ctx, "ten_a", "next")
		mustNoErr(t, err)
		mustEqual(t, got.ParentID, "rt")
		mustEqual(t, got.DPoPJKT, "key")
	})
	t.Run("SessionMetadata", func(t *testing.T) {
		repo := open(t, newStore).Sessions()
		s := newSession("ten_a", "s", "h")
		s.Metadata = map[string]string{"initial": "value"}
		mustNoErr(t, repo.Create(ctx, s))
		s.Metadata["initial"] = "changed"
		got, err := repo.Get(ctx, "ten_a", "s")
		mustNoErr(t, err)
		mustEqual(t, got.Metadata["initial"], "value")
		md := map[string]string{"replaced": "value"}
		got, err = repo.UpdateMetadata(ctx, "ten_a", "s", md)
		mustNoErr(t, err)
		mustEqual(t, got.Metadata, md)
		md["replaced"] = "changed"
		got.Metadata["replaced"] = "changed"
		got, err = repo.Get(ctx, "ten_a", "s")
		mustNoErr(t, err)
		mustEqual(t, got.Metadata["replaced"], "value")
		got, err = repo.UpdateMetadata(ctx, "ten_a", "s", nil)
		mustNoErr(t, err)
		mustEqual(t, len(got.Metadata), 0)
		_, err = repo.UpdateMetadata(ctx, "ten_b", "s", md)
		mustErrIs(t, err, store.ErrNotFound)
	})
	t.Run("TransactionRollback", func(t *testing.T) {
		s := open(t, newStore)
		repo := s.RefreshTokens()
		mustNoErr(t, repo.Create(ctx, familyToken("root", "f", true)))
		at := ts(time.Minute)
		mustNoErr(t, repo.Rotate(ctx, "ten_a", "root", familyToken("a", "f", true), at, time.Minute))
		rollback := errors.New("rollback")
		err := s.WithTx(ctx, func(tx store.Store) error {
			r := tx.RefreshTokens()
			if err := r.Rotate(ctx, "ten_a", "a", familyToken("b", "f", true), at, time.Minute); err != nil {
				return err
			}
			if _, err := r.UpdateMetadata(ctx, "ten_a", "root", map[string]string{"x": "y"}); err != nil {
				return err
			}
			if err := r.RecordExchange(ctx, "ten_a", "a", "192.0.2.1", "ua", at); err != nil {
				return err
			}
			return rollback
		})
		mustErrIs(t, err, rollback)
		a, err := repo.Get(ctx, "ten_a", "a")
		mustNoErr(t, err)
		mustEqual(t, a.LastExchangedAt == nil, true)
		mustEqual(t, a.Device == nil, true)
		root, err := repo.Get(ctx, "ten_a", "root")
		mustNoErr(t, err)
		mustEqual(t, len(root.Metadata), 0)
		mustNoErr(t, repo.Rotate(ctx, "ten_a", "root", familyToken("c", "f", true), at, time.Minute))
	})
}

// A conversion starts a fresh family, so a successor can never become a
// sibling of an independently issued token by reusing its family identifier.
func testConversionFreshFamily(t *testing.T, newStore Factory) {
	ctx := context.Background()
	repo := open(t, newStore).RefreshTokens()
	old := familyToken("old", "old-family", false)
	old.Access = ""
	mustNoErr(t, repo.Create(ctx, old))
	other := familyToken("other", "taken-family", true)
	mustNoErr(t, repo.Create(ctx, other))
	got, err := repo.Get(ctx, "ten_a", "old")
	mustNoErr(t, err)
	mustEqual(t, got.Access, "offline")
	for _, family := range []string{"old-family", "taken-family"} {
		next := familyToken("next", family, true)
		mustErrIs(t, repo.ConvertNonRotating(ctx, "ten_a", "old", next), store.ErrConflict)
		_, err := repo.Get(ctx, "ten_a", "old")
		mustNoErr(t, err)
	}
}
