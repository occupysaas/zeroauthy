package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/passhash/passhashtest"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// importedUser stores a user on conn whose identity holds imported.
func importedUser(t *testing.T, db *Database, conn *store.Connection, email, imported string) *store.User {
	t.Helper()
	now := fixedNow()
	u := &store.User{TenantID: conn.TenantID, UserID: "auth0|imp" + email[:3], Email: email, Name: email, Nickname: email[:3],
		Identities: []store.Identity{{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: "imp" + email[:3], ImportedHash: imported}},
		CreatedAt:  now, UpdatedAt: now}
	if err := db.Store.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestImportedLoginUpgrades(t *testing.T) {
	for name, tc := range map[string]struct{ imported, password string }{
		"bcrypt events": {passhashtest.Bcrypt(), passhashtest.BcryptPassword},
		"pbkdf2":        {passhashtest.PBKDF2("imported pw 1"), "imported pw 1"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db, conn := newDB(t)
			u := importedUser(t, db, conn, "ann@example.com", tc.imported)
			// A wrong password keeps the imported hash.
			if _, err := db.Login(ctx, conn, "ann@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password err = %v", err)
			}
			got, _ := db.Store.Users().Get(ctx, conn.TenantID, u.UserID)
			if got.Identities[0].ImportedHash != tc.imported || got.Identities[0].PasswordHash != "" {
				t.Fatalf("identity after wrong password = %+v", got.Identities[0])
			}
			if _, err := db.Login(ctx, conn, "ANN@example.com", tc.password); err != nil {
				t.Fatalf("Login = %v", err)
			}
			got, _ = db.Store.Users().Get(ctx, conn.TenantID, u.UserID)
			id := got.Identities[0]
			if id.ImportedHash != "" || !strings.HasPrefix(id.PasswordHash, "$argon2id$") {
				t.Fatalf("identity after login = %+v", id)
			}
			if ok, _ := secrets.Verify(id.PasswordHash, tc.password); !ok {
				t.Fatal("upgraded hash does not verify")
			}
			// The upgrade adds no history entry, and the next login is native.
			if _, err := db.Login(ctx, conn, "ann@example.com", tc.password); err != nil {
				t.Fatalf("second Login = %v", err)
			}
		})
	}
}

func TestImportedLoginBlocked(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u := importedUser(t, db, conn, "bob@example.com", passhashtest.PBKDF2("pw pw pw 1"))
	u.Blocked = true
	if err := db.Store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "bob@example.com", "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password on blocked user = %v", err)
	}
	if _, err := db.Login(ctx, conn, "bob@example.com", "pw pw pw 1"); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("right password on blocked user = %v", err)
	}
}

func TestImportedLoginUnusable(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	importedUser(t, db, conn, "cat@example.com", passhashtest.Unusable())
	for _, pw := range []string{"anything", "", "x"} {
		if _, err := db.Login(ctx, conn, "cat@example.com", pw); !errors.Is(err, ErrPasswordChangeRequired) {
			t.Fatalf("Login(%q) = %v, want ErrPasswordChangeRequired", pw, err)
		}
	}
	// An unknown user and a user without any hash get the usual answer.
	if _, err := db.Login(ctx, conn, "nobody@example.com", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user = %v", err)
	}
	importedUser(t, db, conn, "dan@example.com", "")
	if _, err := db.Login(ctx, conn, "dan@example.com", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("user without hash = %v", err)
	}
}

func TestResetReplacesImportedHash(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u := importedUser(t, db, conn, "eve@example.com", passhashtest.PBKDF2("old pw 12345"))
	hash, _ := secrets.Hash("new pw 12345")
	if err := db.Store.Users().SetPasswordHash(ctx, conn.TenantID, u.UserID, conn.Name, hash, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "eve@example.com", "old pw 12345"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password after reset = %v", err)
	}
	if _, err := db.Login(ctx, conn, "eve@example.com", "new pw 12345"); err != nil {
		t.Fatalf("new password = %v", err)
	}
}

// raceStore blocks the first UpgradeImportedHash call until release is
// closed, after signalling reached.
type raceStore struct {
	store.Store
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

type raceUsers struct {
	store.Users
	s *raceStore
}

func (s *raceStore) Users() store.Users { return &raceUsers{s.Store.Users(), s} }

func (r *raceUsers) UpgradeImportedHash(ctx context.Context, tenantID, userID, connection, imported, hash string, at time.Time) error {
	r.s.once.Do(func() {
		close(r.s.reached)
		<-r.s.release
	})
	return r.Users.UpgradeImportedHash(ctx, tenantID, userID, connection, imported, hash, at)
}

// A login that verified the old imported hash while an upsert replaced it:
// the upgrade must not land; the password is checked against the new hash.
func TestUpgradeRacesUpsert(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u := importedUser(t, db, conn, "fay@example.com", passhashtest.PBKDF2("old pw 12345"))
	rs := &raceStore{Store: db.Store, reached: make(chan struct{}), release: make(chan struct{})}
	db.Store = rs
	newImported := passhashtest.PBKDF2("new pw 12345")

	done := make(chan error, 1)
	go func() {
		_, err := db.Login(ctx, conn, "fay@example.com", "old pw 12345")
		done <- err
	}()
	<-rs.reached
	cur, err := rs.Store.Users().Get(ctx, conn.TenantID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	cur.Identities[0].ImportedHash = newImported
	if err := rs.Store.Users().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	close(rs.release)
	// The old password verified against the old hash, but the user now
	// holds the new one: the login is checked against what is stored.
	if err := <-done; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login with the old password = %v; want ErrInvalidCredentials", err)
	}
	got, _ := rs.Store.Users().Get(ctx, conn.TenantID, u.UserID)
	if got.Identities[0].ImportedHash != newImported || got.Identities[0].PasswordHash != "" {
		t.Fatalf("upsert was overwritten: %+v", got.Identities[0])
	}
	if _, err := db.Login(ctx, conn, "fay@example.com", "new pw 12345"); err != nil {
		t.Fatal(err)
	}
	got, _ = rs.Store.Users().Get(ctx, conn.TenantID, u.UserID)
	if got.Identities[0].ImportedHash != "" || got.Identities[0].PasswordHash == "" {
		t.Fatalf("not upgraded: %+v", got.Identities[0])
	}
}

func TestImportModeNeverCallsScriptForImportedUser(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	db, conn, fe := importConn(t, st, scripts{
		store.ScriptLogin: func([]any) (any, error) { return nil, errors.New("must not run") },
	})
	importedUser(t, db, conn, "gus@example.com", passhashtest.PBKDF2("gus pw 1234"))
	if _, err := db.Login(ctx, conn, "gus@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if _, err := db.Login(ctx, conn, "gus@example.com", "gus pw 1234"); err != nil {
		t.Fatalf("Login = %v", err)
	}
	if n := scriptCalls(fe, store.ScriptLogin); n != 0 {
		t.Fatalf("login script ran %d times", n)
	}
}
