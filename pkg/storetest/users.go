package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newUser(tenantID, id, email, username string) *store.User {
	return &store.User{
		TenantID:      tenantID,
		UserID:        "auth0|" + id,
		Email:         email,
		EmailVerified: true,
		Username:      username,
		Name:          "User " + id,
		Nickname:      id,
		Picture:       "https://img.test/" + id + ".png",
		Identities: []store.Identity{{
			Connection: "Database", Provider: store.StrategyDatabase, UserID: id, PasswordHash: "$argon2id$hash-" + id,
		}},
		GivenName: "Given " + id, FamilyName: "Family " + id,
		PhoneNumber: "+1555010" + id[len(id)-1:], PhoneVerified: true,
		UserMetadata: map[string]any{"plan": "pro", "nested": map[string]any{"a": []any{"x"}}},
		AppMetadata:  map[string]any{"plan": "gold", "n": float64(3)},
		CreatedAt:    ts(0),
		UpdatedAt:    ts(0),
	}
}

func testUsers(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetFind", func(t *testing.T) {
		s := open(t, newStore)
		want := newUser("ten_a", "u1", "alice@example.test", "alice")
		mustNoErr(t, s.Users().Create(ctx, want))

		got, err := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		for _, login := range []string{"alice@example.test", "alice"} {
			got, err = s.Users().FindByLogin(ctx, "ten_a", "Database", login)
			mustNoErr(t, err)
			mustEqual(t, got.UserID, "auth0|u1")
		}
		_, err = s.Users().FindByLogin(ctx, "ten_a", "OtherConnection", "alice")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().FindByLogin(ctx, "ten_b", "Database", "alice")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().Get(ctx, "ten_b", "auth0|u1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("Uniqueness", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u1", "other@example.test", "other")), store.ErrConflict)
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u2", "alice@example.test", "")), store.ErrConflict)
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u3", "bob@example.test", "alice")), store.ErrConflict)

		otherConn := newUser("ten_a", "u4", "alice@example.test", "alice")
		otherConn.Identities[0].Connection = "Other"
		mustNoErr(t, s.Users().Create(ctx, otherConn))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_b", "u1", "alice@example.test", "alice")))

		// Empty usernames never collide.
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u5", "carol@example.test", "")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u6", "dave@example.test", "")))
	})

	t.Run("Update", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u2", "bob@example.test", "bob")))

		u, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		u.Email = "alice2@example.test"
		u.Blocked = true
		mustNoErr(t, s.Users().Update(ctx, u))
		_, err := s.Users().FindByLogin(ctx, "ten_a", "Database", "alice@example.test")
		mustErrIs(t, err, store.ErrNotFound)
		got, err := s.Users().FindByLogin(ctx, "ten_a", "Database", "alice2@example.test")
		mustNoErr(t, err)
		mustEqual(t, got.Blocked, true)

		u.Email = "bob@example.test"
		mustErrIs(t, s.Users().Update(ctx, u), store.ErrConflict)
		mustErrIs(t, s.Users().Update(ctx, newUser("ten_a", "missing", "m@example.test", "")), store.ErrNotFound)
	})

	t.Run("RecordLogin", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "")))
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour), "10.0.0.1"))
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(2*time.Hour), "10.0.0.2"))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.LoginsCount, 2)
		mustEqual(t, got.LastIP, "10.0.0.2")
		mustEqual(t, got.LastLogin.Equal(ts(2*time.Hour)), true)
		mustErrIs(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|missing", ts(0), ""), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "")
		mustNoErr(t, s.Users().Create(ctx, in))
		in.Identities[0].PasswordHash = "mutated"

		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour), ""))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		got.Identities[0].Connection = "mutated"
		*got.LastLogin = ts(0)

		again, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again.Identities[0], newUser("ten_a", "u1", "alice@example.test", "").Identities[0])
		mustEqual(t, again.LastLogin.Equal(ts(time.Hour)), true)
	})

	t.Run("MetadataIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "alice")
		mustNoErr(t, s.Users().Create(ctx, in))
		in.UserMetadata["plan"] = "mutated"
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		got.UserMetadata["nested"].(map[string]any)["a"] = "mutated"
		again, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again.UserMetadata, map[string]any{"plan": "pro", "nested": map[string]any{"a": []any{"x"}}})
	})

	t.Run("AppMetadataIsCopiedAndNilRoundTrips", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "alice")
		mustNoErr(t, s.Users().Create(ctx, in))
		in.AppMetadata["plan"] = "mutated"
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		got.AppMetadata["n"] = "mutated"
		again, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again.AppMetadata, map[string]any{"plan": "gold", "n": float64(3)})

		plain := newUser("ten_a", "u2", "bob@example.test", "bob")
		plain.AppMetadata = nil
		mustNoErr(t, s.Users().Create(ctx, plain))
		got, _ = s.Users().Get(ctx, "ten_a", "auth0|u2")
		mustEqual(t, got.AppMetadata == nil, true)
		again.AppMetadata = nil
		mustNoErr(t, s.Users().Update(ctx, again))
		got, _ = s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.AppMetadata == nil, true)
	})

	t.Run("SetPasswordHash", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Database", "$argon2id$new", ts(time.Hour)))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Identities[0].PasswordHash, "$argon2id$new")
		mustEqual(t, got.UpdatedAt, ts(time.Hour))
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Other", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|nobody", "Database", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_b", "auth0|u1", "Database", "x", ts(0)), store.ErrNotFound)
	})

	t.Run("UpdateUsernameConflictAndKeepsLoginStats", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u2", "bob@example.test", "bob")))
		taken := newUser("ten_a", "u2", "bob@example.test", "alice")
		mustErrIs(t, s.Users().Update(ctx, taken), store.ErrConflict)

		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour), ""))
		stale := newUser("ten_a", "u1", "alice@example.test", "alice") // LoginsCount 0, LastLogin nil
		stale.Name = "Alice Renamed"
		mustNoErr(t, s.Users().Update(ctx, stale))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Name, "Alice Renamed")
		mustEqual(t, got.LoginsCount, 1)
		mustEqual(t, got.LastLogin != nil && got.LastLogin.Equal(ts(time.Hour)), true)
	})

	t.Run("PhoneAndLastIPRoundTrip", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "alice")
		in.PhoneNumber, in.PhoneVerified = "+14155550100", true
		mustNoErr(t, s.Users().Create(ctx, in))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.PhoneNumber, "+14155550100")
		mustEqual(t, got.PhoneVerified, true)
		mustEqual(t, got.LastIP, "")
		// Update owns phone fields; LastIP belongs to RecordLogin.
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour), "2001:db8::1"))
		got.PhoneNumber, got.PhoneVerified, got.LastIP = "", false, "9.9.9.9"
		mustNoErr(t, s.Users().Update(ctx, got))
		got, _ = s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.PhoneNumber, "")
		mustEqual(t, got.PhoneVerified, false)
		mustEqual(t, got.LastIP, "2001:db8::1")
	})

	t.Run("VersionBumps", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "alice")
		in.Version = 41 // ignored on Create
		mustNoErr(t, s.Users().Create(ctx, in))
		ver := func() int64 {
			t.Helper()
			u, err := s.Users().Get(ctx, "ten_a", "auth0|u1")
			mustNoErr(t, err)
			return u.Version
		}
		mustEqual(t, ver(), int64(0))

		// Other updates, and RecordLogin, leave it alone; the caller's value is ignored.
		u, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		u.Name, u.Version = "Renamed", 99
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(0))
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour), ""))
		mustEqual(t, ver(), int64(0))
		u.Blocked = false
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(0))

		// Email change.
		u.Email = "alice2@example.test"
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(1))
		// Blocked false -> true.
		u.Blocked = true
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(2))
		// Staying blocked, or unblocking, does not bump.
		u.Name = "Again"
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(2))
		u.Blocked = false
		mustNoErr(t, s.Users().Update(ctx, u))
		mustEqual(t, ver(), int64(2))
		// SetPasswordHash.
		mustNoErr(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Database", "$h1", ts(time.Hour)))
		mustEqual(t, ver(), int64(3))
		// A failed SetPasswordHash does not bump.
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Other", "x", ts(0)), store.ErrNotFound)
		mustEqual(t, ver(), int64(3))
		// SetPasswordHashIfEmpty bumps on success only.
		mustErrIs(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|u1", "Database", "$h2", ts(time.Hour)), store.ErrConflict)
		mustEqual(t, ver(), int64(3))
		// BumpVersion.
		n, err := s.Users().BumpVersion(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, int64(4))
		mustEqual(t, ver(), int64(4))
		_, err = s.Users().BumpVersion(ctx, "ten_a", "auth0|missing")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().BumpVersion(ctx, "ten_b", "auth0|u1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("SetPasswordHashIfEmpty", func(t *testing.T) {
		s := open(t, newStore)
		empty := newUser("ten_a", "u1", "alice@example.test", "alice")
		empty.Identities[0].PasswordHash = ""
		mustNoErr(t, s.Users().Create(ctx, empty))
		mustNoErr(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|u1", "Database", "$first", ts(time.Hour)))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Identities[0].PasswordHash, "$first")
		mustEqual(t, got.UpdatedAt, ts(time.Hour))
		mustEqual(t, got.Version, int64(1))
		mustErrIs(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|u1", "Database", "$second", ts(2*time.Hour)), store.ErrConflict)
		got, _ = s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Identities[0].PasswordHash, "$first")
		mustEqual(t, got.UpdatedAt, ts(time.Hour))
		mustEqual(t, got.Version, int64(1))
		mustErrIs(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|u1", "Other", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|nobody", "Database", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHashIfEmpty(ctx, "ten_b", "auth0|u1", "Database", "x", ts(0)), store.ErrNotFound)
	})

	t.Run("SetPasswordHashIfEmptyRace", func(t *testing.T) {
		s := open(t, newStore)
		empty := newUser("ten_a", "u1", "alice@example.test", "alice")
		empty.Identities[0].PasswordHash = ""
		mustNoErr(t, s.Users().Create(ctx, empty))
		errs := parallel(20, func(i int) error {
			if i%2 == 0 {
				return s.Users().SetPasswordHashIfEmpty(ctx, "ten_a", "auth0|u1", "Database", fmt.Sprint("$ifempty", i), ts(time.Hour))
			}
			return s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Database", fmt.Sprint("$set", i), ts(time.Hour))
		})
		wins := 0
		for i, err := range errs {
			switch {
			case err == nil:
				if i%2 == 0 {
					wins++
				}
			case i%2 == 0 && errors.Is(err, store.ErrConflict):
			default:
				t.Errorf("call %d: unexpected %v", i, err)
			}
		}
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		// All ten plain sets succeed. At most one if-empty write can win: it
		// has to run before every set, so a set always comes after it and the
		// final hash is never an if-empty one.
		if wins > 1 {
			t.Errorf("%d if-empty writes succeeded, want at most 1", wins)
		}
		mustEqual(t, got.Version, int64(10+wins))
		if h := got.Identities[0].PasswordHash; !strings.HasPrefix(h, "$set") {
			t.Errorf("final hash %q was written by an if-empty call", h)
		}
	})

	t.Run("FindByEmail", func(t *testing.T) {
		s := open(t, newStore)
		a := newUser("ten_a", "a", "shared@example.test", "")
		b := newUser("ten_a", "B", "shared@example.test", "")
		b.Identities[0].Connection = "Other"
		c := newUser("ten_a", "c", "different@example.test", "")
		d := newUser("ten_b", "a", "shared@example.test", "")
		for _, u := range []*store.User{a, b, c, d} {
			mustNoErr(t, s.Users().Create(ctx, u))
		}
		got, err := s.Users().FindByEmail(ctx, "ten_a", "shared@example.test")
		mustNoErr(t, err)
		mustEqual(t, len(got), 2)
		mustEqual(t, got[0].UserID, "auth0|B") // byte order: upper case first
		mustEqual(t, got[1].UserID, "auth0|a")
		got, err = s.Users().FindByEmail(ctx, "ten_a", "nobody@example.test")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
		got, err = s.Users().FindByEmail(ctx, "ten_a", "")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
		got, err = s.Users().FindByEmail(ctx, "ten_zz", "shared@example.test")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
	})

	t.Run("ConcurrentCreateDistinct", func(t *testing.T) {
		s := open(t, newStore)
		for i, err := range parallel(16, func(i int) error {
			return s.Users().Create(ctx, newUser("ten_a", fmt.Sprint("u", i), fmt.Sprintf("e%d@example.test", i), fmt.Sprint("name", i)))
		}) {
			if err != nil {
				t.Errorf("create %d: %v", i, err)
			}
		}
	})

	t.Run("ConcurrentCreateSameLogin", func(t *testing.T) {
		s := open(t, newStore)
		errs := parallel(16, func(i int) error {
			u := newUser("ten_a", fmt.Sprint("u", i), "same@example.test", fmt.Sprint("name", i))
			u.Identities = []store.Identity{{Connection: "A", Provider: store.StrategyDatabase, UserID: u.UserID}, {Connection: "B", Provider: store.StrategyDatabase, UserID: u.UserID}}
			if i%2 == 1 {
				u.Identities[0], u.Identities[1] = u.Identities[1], u.Identities[0]
			}
			return s.Users().Create(ctx, u)
		})
		ok := 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, store.ErrConflict):
				t.Errorf("create %d: want ErrConflict, got %v", i, err)
			}
		}
		if ok != 1 {
			t.Errorf("%d creates succeeded, want exactly 1", ok)
		}
	})

	t.Run("CrossedUpdateConflicts", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "a", "a@example.test", "")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "b", "b@example.test", "")))
		errs := parallel(2, func(i int) error {
			if i == 0 {
				return s.Users().Update(ctx, newUser("ten_a", "a", "b@example.test", ""))
			}
			return s.Users().Update(ctx, newUser("ten_a", "b", "a@example.test", ""))
		})
		for i, err := range errs {
			if !errors.Is(err, store.ErrConflict) {
				t.Errorf("update %d: want ErrConflict, got %v", i, err)
			}
		}
		for id, email := range map[string]string{"a": "a@example.test", "b": "b@example.test"} {
			got, err := s.Users().Get(ctx, "ten_a", "auth0|"+id)
			mustNoErr(t, err)
			mustEqual(t, got.Email, email)
		}
	})
}
