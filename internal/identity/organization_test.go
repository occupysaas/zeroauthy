package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A registration commit failure must undo both the new account and membership.
func TestOrganizationSignupAtomic(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	if err := db.Store.Tenants().Create(ctx, &store.Tenant{ID: conn.TenantID, Name: "example"}); err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: conn.TenantID, ID: "org_0000000000000001", Name: "example", DisplayName: "Example"}
	if err := db.Store.Organizations().Create(ctx, org, nil); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("commit failed")
	_, err := db.Signup(ctx, conn, SignupInput{Email: "org@example.com", Password: "correct horse", Actions: SignupActions{Commit: func(ctx context.Context, tx store.Store, u *store.User) error {
		if err := tx.Organizations().AddMembers(ctx, conn.TenantID, org.ID, []string{u.UserID}); err != nil {
			return err
		}
		return stop
	}}})
	if !errors.Is(err, stop) {
		t.Fatalf("commit error: %v", err)
	}
	if _, err = db.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, "org@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed signup persisted: %v", err)
	}
	members, err := db.Store.Organizations().Members(ctx, conn.TenantID, org.ID, store.OrgPage{})
	if err != nil || len(members.Items) != 0 {
		t.Fatalf("members survived rollback: %+v %v", members, err)
	}
}

// Login must offer a commit hook inside the user-write transaction. The hook
// can fail local first-login writes, rather than leaving a partial identity.
func TestOrganizationLoginCommit(t *testing.T) {
	db, conn := newDB(t)
	type committer interface {
		LoginWithCheckAndCommit(context.Context, *store.Connection, string, string, func(context.Context) error, func(context.Context, store.Store, *store.User) error) (*store.User, error)
	}
	login, ok := any(db).(committer)
	if !ok {
		t.Fatal("database login lacks atomic user-write commit hook")
	}
	u, err := db.Signup(context.Background(), conn, SignupInput{Email: "member@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("membership storage unavailable")
	_, err = login.LoginWithCheckAndCommit(context.Background(), conn, u.Email, "correct horse", nil, func(context.Context, store.Store, *store.User) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("commit error lost: %v", err)
	}
}

func TestOrganizationCustomLoginCommitRollback(t *testing.T) {
	for _, importMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "import"}[importMode], func(t *testing.T) {
			users := map[string]*legacyUser{"new@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "new@legacy.test"}}}
			var db *Database
			var conn *store.Connection
			if importMode {
				db, conn, _ = importConn(t, memory.New(), scripts{store.ScriptLogin: checkLogin(users)})
			} else {
				db, conn, _ = legacyConn(t, scripts{store.ScriptLogin: checkLogin(users)})
			}
			stop := errors.New("membership storage unavailable")
			ctx := context.Background()
			_, err := db.LoginWithCheckAndCommit(ctx, conn, "new@legacy.test", "legacy pw", nil, func(ctx context.Context, tx store.Store, u *store.User) error {
				// The user exists within the hook, and disappears when the hook fails.
				if _, err := tx.Users().Get(ctx, conn.TenantID, "auth0|42"); err != nil {
					t.Fatal(err)
				}
				return stop
			})
			if !errors.Is(err, stop) {
				t.Fatalf("commit error: %v", err)
			}
			if _, err = db.Store.Users().Get(ctx, conn.TenantID, "auth0|42"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("partial first login retained: %v", err)
			}
		})
	}
}
