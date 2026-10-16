package identity

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

type scripts = map[string]func([]any) (any, error)

// legacyConn returns a Database whose legacy connection runs scripts, the
// connection, and the executor that records calls.
func legacyConn(t *testing.T, s scripts) (*Database, *store.Connection, *customdb.FuncExecutor) {
	t.Helper()
	return customConn(t, memory.New(), false, s)
}

// importConn is legacyConn with the connection in import mode, on st.
func importConn(t *testing.T, st store.Store, s scripts) (*Database, *store.Connection, *customdb.FuncExecutor) {
	t.Helper()
	return customConn(t, st, true, s)
}

func customConn(t *testing.T, st store.Store, importMode bool, s scripts) (*Database, *store.Connection, *customdb.FuncExecutor) {
	t.Helper()
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_a", Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	conn := &store.Connection{TenantID: "ten_a", ID: "con_l", Name: "Legacy", Strategy: store.StrategyDatabase,
		EnabledDatabaseCustomization: true, ImportMode: importMode, CustomScripts: map[string]string{}}
	for _, name := range store.ScriptNames {
		conn.CustomScripts[name] = "function " + name + "() {}"
	}
	if err := st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	fe := &customdb.FuncExecutor{Funcs: s}
	return &Database{Store: st, Now: fixedNow, Scripts: &customdb.Client{Exec: fe}, Log: slog.New(slog.DiscardHandler)}, conn, fe
}

// legacyStore checks passwords against a fixed table, as a legacy database
// would. Each entry is login -> password, profile.
type legacyUser struct {
	password string
	profile  map[string]any
}

func checkLogin(users map[string]*legacyUser) func([]any) (any, error) {
	return func(args []any) (any, error) {
		u := users[strings.ToLower(args[0].(string))]
		if u == nil || u.password != args[1].(string) {
			return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials, Message: "wrong"}
		}
		return u.profile, nil
	}
}

func TestLegacyLoginCreatesLocalUser(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{
		"user_id": 42, "email": "Alice@Legacy.test", "email_verified": true, "app_metadata": map[string]any{"plan": "gold"},
	}}}
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: checkLogin(users)})
	ctx := context.Background()
	u, err := db.Login(ctx, conn, " Alice@legacy.test ", "legacy pw")
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "auth0|42" || u.Email != "alice@legacy.test" || !u.EmailVerified || u.AppMetadata["plan"] != "gold" ||
		u.Name != "alice@legacy.test" || u.Nickname != "alice" {
		t.Fatalf("user = %+v", u)
	}
	if id := u.Identities; len(id) != 1 || id[0] != (store.Identity{Connection: "Legacy", Provider: "auth0", UserID: "42"}) {
		t.Fatalf("identities = %+v", id)
	}
	if got, err := db.Store.Users().FindByLogin(ctx, "ten_a", "Legacy", "alice@legacy.test"); err != nil || got.UserID != "auth0|42" {
		t.Fatalf("FindByLogin = %+v, %v", got, err)
	}
}

func TestLegacyLoginIdentifierAsTyped(t *testing.T) {
	var got string
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func(args []any) (any, error) {
		got = args[0].(string)
		return map[string]any{"user_id": "1", "email": "a@b.test"}, nil
	}})
	if _, err := db.Login(context.Background(), conn, "  MixedCase ", "pw"); err != nil {
		t.Fatal(err)
	}
	if got != "MixedCase" {
		t.Fatalf("identifier = %q", got)
	}
}

func TestLegacyLoginAlwaysCallsScript(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "alice@legacy.test"}}}
	db, conn, fe := legacyConn(t, scripts{store.ScriptLogin: checkLogin(users)})
	ctx := context.Background()
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if n := len(fe.Requests()); n != 2 {
		t.Fatalf("script calls = %d, want 2", n)
	}
}

func TestLegacyLoginSyncsRootAttributes(t *testing.T) {
	for _, mode := range []string{"", store.RootAttributesOnFirstLogin} {
		t.Run("mode="+mode, func(t *testing.T) {
			profile := map[string]any{"user_id": "42", "email": "alice@legacy.test", "name": "First",
				"user_metadata": map[string]any{"v": "1"}}
			db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) { return profile, nil }})
			conn.SetUserRootAttributes = mode
			ctx := context.Background()
			if _, err := db.Login(ctx, conn, "alice@legacy.test", "pw"); err != nil {
				t.Fatal(err)
			}
			profile = map[string]any{"user_id": "42", "email": "alice2@legacy.test", "email_verified": true, "name": "Second",
				"user_metadata": map[string]any{"v": "2"}}
			u, err := db.Login(ctx, conn, "alice@legacy.test", "pw")
			if err != nil {
				t.Fatal(err)
			}
			wantName := "Second"
			if mode == store.RootAttributesOnFirstLogin {
				wantName = "First"
			}
			if u.Name != wantName || u.Email != "alice2@legacy.test" || !u.EmailVerified || u.UserMetadata["v"] != "1" {
				t.Fatalf("user = %+v", u)
			}
		})
	}
}

func TestLegacyLoginRejectsBadProfile(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		return map[string]any{"user_id": "a|b", "email": "a@b.test"}, nil
	}})
	if _, err := db.Login(context.Background(), conn, "a@b.test", "pw"); !errors.Is(err, ErrScript) || !errors.Is(err, customdb.ErrBadProfile) {
		t.Fatalf("err = %v", err)
	}
	if _, err := db.Store.Users().FindByLogin(context.Background(), "ten_a", "Legacy", "a@b.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a user was created: %v", err)
	}
}

func TestLegacyLoginCollision(t *testing.T) {
	ctx := context.Background()
	t.Run("other connection", func(t *testing.T) {
		db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
			return map[string]any{"user_id": "42", "email": "new@b.test", "name": "Changed"}, nil
		}})
		other := &store.User{TenantID: "ten_a", UserID: "auth0|42", Email: "old@b.test", Name: "Old",
			Identities: []store.Identity{{Connection: "Elsewhere", Provider: "auth0", UserID: "42", PasswordHash: "x"}}}
		if err := db.Store.Users().Create(ctx, other); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Login(ctx, conn, "new@b.test", "pw"); !errors.Is(err, ErrScript) {
			t.Fatalf("err = %v", err)
		}
		if u, _ := db.Store.Users().Get(ctx, "ten_a", "auth0|42"); u.Email != "old@b.test" || u.Name != "Old" {
			t.Fatalf("existing user changed: %+v", u)
		}
	})
	t.Run("email held by another user", func(t *testing.T) {
		db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
			return map[string]any{"user_id": "42", "email": "taken@b.test"}, nil
		}})
		holder := &store.User{TenantID: "ten_a", UserID: "auth0|7", Email: "taken@b.test", Name: "Holder",
			Identities: []store.Identity{{Connection: "Legacy", Provider: "auth0", UserID: "7"}}}
		if err := db.Store.Users().Create(ctx, holder); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Login(ctx, conn, "taken@b.test", "pw"); !errors.Is(err, ErrScript) {
			t.Fatalf("err = %v", err)
		}
		if u, _ := db.Store.Users().Get(ctx, "ten_a", "auth0|7"); u.Name != "Holder" {
			t.Fatalf("holder changed: %+v", u)
		}
		if _, err := db.Store.Users().Get(ctx, "ten_a", "auth0|42"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("colliding user created: %v", err)
		}
	})
}

func TestLegacyLoginBlocked(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "alice@legacy.test"}}}
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: checkLogin(users)})
	ctx := context.Background()
	u, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw")
	if err != nil {
		t.Fatal(err)
	}
	u.Blocked = true
	if err := db.Store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password on blocked user = %v", err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("blocked = %v", err)
	}
}

func TestLegacyLoginUnauthorized(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "account suspended"}
	}})
	_, err := db.Login(context.Background(), conn, "a@b.test", "pw")
	var ue *UnauthorizedError
	if !errors.As(err, &ue) || ue.Message != "account suspended" {
		t.Fatalf("err = %v", err)
	}
}

func TestLegacyLoginScriptFailure(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) { return nil, customdb.ErrTimeout }})
	if _, err := db.Login(context.Background(), conn, "a@b.test", "pw"); !errors.Is(err, ErrScript) || !errors.Is(err, customdb.ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

// signupScripts is a legacy store that records the order of script calls.
type signupScripts struct {
	mu      sync.Mutex
	calls   []string
	users   map[string]*legacyUser
	created map[string]any
}

func (s *signupScripts) record(name string) {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
}

func (s *signupScripts) funcs() scripts {
	login := checkLogin(s.users)
	return scripts{
		store.ScriptGetUser: func(args []any) (any, error) {
			s.record("get_user")
			if u := s.users[args[0].(string)]; u != nil {
				return u.profile, nil
			}
			return nil, nil
		},
		store.ScriptCreate: func(args []any) (any, error) {
			s.record("create")
			s.created = args[0].(map[string]any)
			email := s.created["email"].(string)
			s.users[email] = &legacyUser{s.created["password"].(string), map[string]any{"user_id": 99, "email": email}}
			return nil, nil
		},
		store.ScriptLogin: func(args []any) (any, error) {
			s.record("login")
			return login(args)
		},
	}
}

func TestLegacySignup(t *testing.T) {
	ctx := context.Background()
	t.Run("creates", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, _ := legacyConn(t, s.funcs())
		u, err := db.Signup(ctx, conn, SignupInput{ClientID: "app", Email: "New@b.test", Password: "long enough pw",
			UserMetadata: map[string]any{"k": "v"}})
		if err != nil {
			t.Fatal(err)
		}
		if u.UserID != "auth0|99" || u.Email != "new@b.test" || u.Identities[0].PasswordHash != "" {
			t.Fatalf("user = %+v", u)
		}
		if strings.Join(s.calls, ",") != "get_user,create,login" {
			t.Fatalf("calls = %v", s.calls)
		}
		c := s.created
		if c["tenant"] != "acme" || c["client_id"] != "app" || c["connection"] != "Legacy" || c["email"] != "new@b.test" ||
			c["password"] != "long enough pw" || c["user_metadata"].(map[string]any)["k"] != "v" {
			t.Fatalf("create got %v", c)
		}
	})
	t.Run("username checked too", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, _ := legacyConn(t, s.funcs())
		conn.RequiresUsername = true
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Username: "Nb", Password: "long enough pw"}); err != nil {
			t.Fatal(err)
		}
		if strings.Join(s.calls, ",") != "get_user,get_user,create,login" || s.created["username"] != "nb" {
			t.Fatalf("calls = %v, created = %v", s.calls, s.created)
		}
	})
	t.Run("get_user finds the user", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{"old@b.test": {"pw", map[string]any{"user_id": "1", "email": "old@b.test"}}}}
		db, conn, _ := legacyConn(t, s.funcs())
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "old@b.test", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("err = %v", err)
		}
		if strings.Join(s.calls, ",") != "get_user" {
			t.Fatalf("calls = %v", s.calls)
		}
	})
	t.Run("create says user_exists", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		f := s.funcs()
		f[store.ScriptCreate] = func([]any) (any, error) {
			return nil, &customdb.ScriptError{Kind: customdb.KindValidation, Code: "user_exists", Message: "exists"}
		}
		db, conn, _ := legacyConn(t, f)
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("create validation", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		f := s.funcs()
		f[store.ScriptCreate] = func([]any) (any, error) {
			return nil, &customdb.ScriptError{Kind: customdb.KindValidation, Code: "bad", Message: "domain not allowed"}
		}
		db, conn, _ := legacyConn(t, f)
		var pe *PolicyError
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.As(err, &pe) || pe.Reason != "domain not allowed" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("password policy", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, fe := legacyConn(t, s.funcs())
		var pe *PolicyError
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "short"}); !errors.As(err, &pe) {
			t.Fatalf("err = %v", err)
		}
		if len(fe.Requests()) != 0 {
			t.Fatal("a script ran")
		}
	})
	t.Run("confirming login fails", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		f := s.funcs()
		f[store.ScriptLogin] = func([]any) (any, error) {
			return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials}
		}
		db, conn, _ := legacyConn(t, f)
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.Is(err, ErrScript) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestLegacyFindForReset(t *testing.T) {
	ctx := context.Background()
	users := map[string]*legacyUser{
		"alice@legacy.test": {"pw", map[string]any{"user_id": "42", "email": "alice@legacy.test", "username": "alice1", "name": "Alice"}},
		"alice1":            {"pw", map[string]any{"user_id": "42", "email": "alice@legacy.test", "username": "alice1"}},
	}
	db, conn, fe := legacyConn(t, scripts{store.ScriptGetUser: func(args []any) (any, error) {
		if u := users[args[0].(string)]; u != nil {
			return u.profile, nil
		}
		return nil, nil
	}})
	if _, err := db.FindForReset(ctx, conn, "nobody@legacy.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	u, err := db.FindForReset(ctx, conn, " Alice@Legacy.test")
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "auth0|42" || u.Identities[0].PasswordHash != "" || u.Email != "alice@legacy.test" {
		t.Fatalf("user = %+v", u)
	}
	// A username is not an email: the script is not asked.
	n := len(fe.Requests())
	if _, err := db.FindForReset(ctx, conn, "alice1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("username = %v", err)
	}
	if len(fe.Requests()) != n {
		t.Fatal("get_user ran for a username")
	}
}

func TestLegacyFindForResetEmailMustMatch(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptGetUser: func([]any) (any, error) {
		return map[string]any{"user_id": "42", "email": "someone-else@legacy.test"}, nil
	}})
	if _, err := db.FindForReset(context.Background(), conn, "alice@legacy.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestLocalFindForReset(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	if _, err := db.Signup(ctx, conn, SignupInput{Email: "bob@example.com", Password: "bobs password"}); err != nil {
		t.Fatal(err)
	}
	if u, err := db.FindForReset(ctx, conn, "BOB@example.com"); err != nil || u.Email != "bob@example.com" {
		t.Fatalf("FindForReset = %+v, %v", u, err)
	}
	if _, err := db.FindForReset(ctx, conn, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
}

func TestChangeLegacyPassword(t *testing.T) {
	ctx := context.Background()
	user := &store.User{UserID: "auth0|42", Email: "alice@legacy.test"}
	for _, tc := range []struct {
		name   string
		result any
		err    error
		check  func(error) bool
	}{
		{"changed", true, nil, func(err error) bool { return err == nil }},
		{"not changed", false, nil, func(err error) bool { return errors.Is(err, ErrPasswordNotChanged) }},
		{"error", nil, errors.New("db down"), func(err error) bool { return errors.Is(err, ErrScript) }},
		{"unauthorized", nil, &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "no"}, func(err error) bool {
			var ue *UnauthorizedError
			return errors.As(err, &ue) && ue.Message == "no"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var args []any
			db, conn, _ := legacyConn(t, scripts{store.ScriptChangePassword: func(a []any) (any, error) {
				args = a
				return tc.result, tc.err
			}})
			err := db.ChangeLegacyPassword(ctx, conn, user, "new password")
			if !tc.check(err) {
				t.Fatalf("err = %v", err)
			}
			if len(args) != 2 || args[0] != "alice@legacy.test" || args[1] != "new password" {
				t.Fatalf("args = %v", args)
			}
		})
	}
}

func TestCustomWithoutScripts(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{})
	db.Scripts = nil
	if _, err := db.Login(context.Background(), conn, "a@b.test", "pw"); !errors.Is(err, ErrScript) {
		t.Fatalf("err = %v", err)
	}
}

// staleUsers misses the user on its first Get, as a Get that ran just
// before a concurrent first login created the user would.
type staleUsers struct {
	store.Users
	missed bool
}

func (s *staleUsers) Get(ctx context.Context, tenantID, userID string) (*store.User, error) {
	if !s.missed {
		s.missed = true
		return nil, store.ErrNotFound
	}
	return s.Users.Get(ctx, tenantID, userID)
}

type staleStore struct {
	store.Store
	users *staleUsers
}

func (s staleStore) Users() store.Users { return s.users }

func TestLegacyFirstLoginRace(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		return map[string]any{"user_id": "42", "email": "alice@legacy.test", "name": "Alice"}, nil
	}})
	ctx := context.Background()
	// The other first login has already created the user.
	other := &store.User{TenantID: "ten_a", UserID: "auth0|42", Email: "alice@legacy.test",
		Identities: []store.Identity{{Connection: "Legacy", Provider: "auth0", UserID: "42"}}}
	if err := db.Store.Users().Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	db.Store = staleStore{Store: db.Store, users: &staleUsers{Users: db.Store.Users()}}
	u, err := db.Login(ctx, conn, "alice@legacy.test", "pw")
	if err != nil || u.UserID != "auth0|42" || u.Name != "Alice" {
		t.Fatalf("Login = %+v, %v", u, err)
	}
}

func TestLegacyConcurrentFirstLogins(t *testing.T) {
	const n = 8
	arrived := make(chan struct{}, n)
	release := make(chan struct{})
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		arrived <- struct{}{}
		<-release // every login reaches the store at about the same time
		return map[string]any{"user_id": "42", "email": "alice@legacy.test"}, nil
	}})
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := db.Login(context.Background(), conn, "alice@legacy.test", "pw")
			errs <- err
		}()
	}
	for range n {
		<-arrived
	}
	close(release)
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent first login: %v", err)
		}
	}
}

// Errors a script raised count as failed attempts; failures to get an
// answer at all are ErrScriptUnavailable (D-0023).
func TestScriptUnavailableClassification(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		result      any
		err         error
		mutate      func(*Database, *store.Connection)
		unavailable bool
	}{
		{"script error", nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "bad"}, nil, false},
		{"validation error", nil, &customdb.ScriptError{Kind: customdb.KindValidation, Message: "bad"}, nil, false},
		{"bad profile", map[string]any{"user_id": "a|b", "email": "a@b.test"}, nil, nil, false},
		{"unrecognised error", nil, errors.New("new kind"), nil, false},
		{"deadline exceeded", nil, context.DeadlineExceeded, nil, true},
		{"timeout", nil, customdb.ErrTimeout, nil, true},
		{"unavailable", nil, customdb.ErrUnavailable, nil, true},
		{"cancelled", nil, context.Canceled, nil, true},
		{"no script", nil, nil, func(_ *Database, c *store.Connection) { c.CustomScripts[store.ScriptLogin] = "" }, true},
		{"no client", nil, nil, func(d *Database, _ *store.Connection) { d.Scripts = nil }, true},
		{"config", nil, nil, func(_ *Database, c *store.Connection) { c.ConfigurationSealed = []byte("not sealed") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) { return tc.result, tc.err }})
			if tc.mutate != nil {
				tc.mutate(db, conn)
			}
			_, err := db.Login(ctx, conn, "a@b.test", "pw")
			if !errors.Is(err, ErrScript) || errors.Is(err, ErrScriptUnavailable) != tc.unavailable {
				t.Fatalf("err = %v, want ErrScript with unavailable=%v", err, tc.unavailable)
			}
		})
	}
	t.Run("unrecognised error is counted", func(t *testing.T) {
		db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) { return nil, errors.New("new kind") }})
		if _, err := db.Login(ctx, conn, "a@b.test", "pw"); !ScriptRaised(err) {
			t.Fatalf("err = %v, want ScriptRaised", err)
		}
	})
	t.Run("collision", func(t *testing.T) {
		db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
			return map[string]any{"user_id": "42", "email": "a@b.test"}, nil
		}})
		if err := db.Store.Users().Create(ctx, &store.User{TenantID: "ten_a", UserID: "auth0|42",
			Identities: []store.Identity{{Connection: "Elsewhere", Provider: "auth0", UserID: "42"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Login(ctx, conn, "a@b.test", "pw"); !errors.Is(err, ErrScript) || errors.Is(err, ErrScriptUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestLegacySignupConfirmRefusal(t *testing.T) {
	s := &signupScripts{users: map[string]*legacyUser{}}
	f := s.funcs()
	f[store.ScriptLogin] = func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "verify your email first"}
	}
	db, conn, _ := legacyConn(t, f)
	_, err := db.Signup(context.Background(), conn, SignupInput{Email: "n@b.test", Password: "long enough pw"})
	var ue *UnauthorizedError
	if !errors.As(err, &ue) || ue.Message != "verify your email first" || errors.Is(err, ErrScript) {
		t.Fatalf("err = %v", err)
	}
}

// passwordHashOf returns the stored password hash of userID on conn.
func passwordHashOf(t *testing.T, db *Database, conn *store.Connection, userID string) string {
	t.Helper()
	u, err := db.Store.Users().Get(context.Background(), conn.TenantID, userID)
	if err != nil {
		t.Fatalf("Get %s: %v", userID, err)
	}
	for _, id := range u.Identities {
		if id.Connection == conn.Name {
			return id.PasswordHash
		}
	}
	t.Fatalf("%s has no identity on %s", userID, conn.Name)
	return ""
}

// scriptCalls counts the recorded runs of script.
func scriptCalls(fe *customdb.FuncExecutor, script string) int {
	n := 0
	for _, r := range fe.Requests() {
		if r.Script == script {
			n++
		}
	}
	return n
}

func TestImportFirstLoginMigrates(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{
		"user_id": 42, "email": "Alice@Legacy.test", "name": "Alice", "app_metadata": map[string]any{"plan": "gold"},
	}}}
	db, conn, fe := importConn(t, memory.New(), scripts{store.ScriptLogin: checkLogin(users)})
	ctx := context.Background()
	u, err := db.Login(ctx, conn, " Alice@legacy.test ", "legacy pw")
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "auth0|42" || u.Email != "alice@legacy.test" || u.Name != "Alice" || u.AppMetadata["plan"] != "gold" {
		t.Fatalf("user = %+v", u)
	}
	hash := passwordHashOf(t, db, conn, "auth0|42")
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("stored hash = %q", hash)
	}
	if ok, err := secrets.Verify(hash, "legacy pw"); err != nil || !ok {
		t.Fatalf("stored hash does not verify: %v, %v", ok, err)
	}
	u, err = db.Login(ctx, conn, "alice@legacy.test", "legacy pw")
	if err != nil || u.UserID != "auth0|42" {
		t.Fatalf("second login = %+v, %v", u, err)
	}
	if n := len(fe.Requests()); n != 1 {
		t.Fatalf("script calls = %d, want 1", n)
	}
}

func TestImportWrongPasswordAfterMigration(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "alice@legacy.test"}}}
	db, conn, fe := importConn(t, memory.New(), scripts{store.ScriptLogin: checkLogin(users)})
	ctx := context.Background()
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if n := len(fe.Requests()); n != 1 {
		t.Fatalf("script calls = %d, want 1", n)
	}
}

func TestImportUnknownUser(t *testing.T) {
	db, conn, fe := importConn(t, memory.New(), scripts{store.ScriptLogin: checkLogin(map[string]*legacyUser{})})
	ctx := context.Background()
	if _, err := db.Login(ctx, conn, "nobody@legacy.test", "pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
	if n := len(fe.Requests()); n != 1 {
		t.Fatalf("script calls = %d, want 1", n)
	}
	if _, err := db.Store.Users().FindByLogin(ctx, "ten_a", "Legacy", "nobody@legacy.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a user was created: %v", err)
	}
}

// Import mode keeps the throttle classification of legacy logins (D-0023).
func TestImportScriptFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		unavailable bool
	}{
		{"raised", &customdb.ScriptError{Kind: customdb.KindError, Message: "bad"}, false},
		{"timeout", customdb.ErrTimeout, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, conn, _ := importConn(t, memory.New(), scripts{store.ScriptLogin: func([]any) (any, error) { return nil, tc.err }})
			_, err := db.Login(context.Background(), conn, "a@b.test", "pw")
			if !errors.Is(err, ErrScript) || errors.Is(err, ErrScriptUnavailable) != tc.unavailable {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("unauthorized", func(t *testing.T) {
		db, conn, _ := importConn(t, memory.New(), scripts{store.ScriptLogin: func([]any) (any, error) {
			return nil, &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "suspended"}
		}})
		var ue *UnauthorizedError
		if _, err := db.Login(context.Background(), conn, "a@b.test", "pw"); !errors.As(err, &ue) || ue.Message != "suspended" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("collision", func(t *testing.T) {
		db, conn, _ := importConn(t, memory.New(), scripts{store.ScriptLogin: func([]any) (any, error) {
			return map[string]any{"user_id": "42", "email": "a@b.test"}, nil
		}})
		ctx := context.Background()
		if err := db.Store.Users().Create(ctx, &store.User{TenantID: "ten_a", UserID: "auth0|42", Email: "old@b.test",
			Identities: []store.Identity{{Connection: "Elsewhere", Provider: "auth0", UserID: "42", PasswordHash: "x"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Login(ctx, conn, "a@b.test", "pw"); !ScriptRaised(err) {
			t.Fatalf("err = %v", err)
		}
		if u, _ := db.Store.Users().Get(ctx, "ten_a", "auth0|42"); u.Email != "old@b.test" || u.Identities[0].PasswordHash != "x" {
			t.Fatalf("existing user changed: %+v", u)
		}
	})
}

func openSQLite(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestImportConcurrentFirstLogin(t *testing.T) {
	for name, open := range map[string]func(*testing.T) store.Store{
		"memory": func(*testing.T) store.Store { return memory.New() },
		"sqlite": openSQLite,
	} {
		t.Run(name, func(t *testing.T) {
			const n = 10
			db, conn, _ := importConn(t, open(t), scripts{store.ScriptLogin: func(args []any) (any, error) {
				time.Sleep(20 * time.Millisecond)
				if args[1] != "legacy pw" {
					return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials}
				}
				return map[string]any{"user_id": "42", "email": "alice@legacy.test"}, nil
			}})
			var start, done sync.WaitGroup
			start.Add(1)
			errs := make([]error, n)
			for i := range n {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					_, errs[i] = db.Login(context.Background(), conn, "alice@legacy.test", "legacy pw")
				}()
			}
			start.Done()
			done.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("login %d: %v", i, err)
				}
			}
			ctx := context.Background()
			u, err := db.Store.Users().FindByLogin(ctx, "ten_a", "Legacy", "alice@legacy.test")
			if err != nil || u.UserID != "auth0|42" || len(u.Identities) != 1 {
				t.Fatalf("FindByLogin = %+v, %v", u, err)
			}
			if ok, err := secrets.Verify(u.Identities[0].PasswordHash, "legacy pw"); err != nil || !ok {
				t.Fatalf("stored hash: %v, %v", ok, err)
			}
		})
	}
}

func TestImportSignup(t *testing.T) {
	ctx := context.Background()
	t.Run("get_user finds the user", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{"old@b.test": {"pw", map[string]any{"user_id": "1", "email": "old@b.test"}}}}
		db, conn, _ := importConn(t, memory.New(), s.funcs())
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "Old@b.test", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("err = %v", err)
		}
		if strings.Join(s.calls, ",") != "get_user" {
			t.Fatalf("calls = %v", s.calls)
		}
		if _, err := db.Store.Users().FindByLogin(ctx, "ten_a", "Legacy", "old@b.test"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a user was created: %v", err)
		}
	})
	t.Run("get_user finds the username", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{"taken": {"pw", map[string]any{"user_id": "1", "username": "taken"}}}}
		db, conn, _ := importConn(t, memory.New(), s.funcs())
		conn.RequiresUsername = true
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Username: "Taken", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("err = %v", err)
		}
		if strings.Join(s.calls, ",") != "get_user,get_user" {
			t.Fatalf("calls = %v", s.calls)
		}
	})
	t.Run("get_user returns null", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, fe := importConn(t, memory.New(), s.funcs())
		u, err := db.Signup(ctx, conn, SignupInput{ClientID: "app", Email: "New@b.test", Password: "long enough pw", Name: "New"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(s.calls, ",") != "get_user" {
			t.Fatalf("calls = %v", s.calls)
		}
		if !strings.HasPrefix(u.UserID, "auth0|") || u.Email != "new@b.test" || u.Name != "New" {
			t.Fatalf("user = %+v", u)
		}
		if ok, err := secrets.Verify(passwordHashOf(t, db, conn, u.UserID), "long enough pw"); err != nil || !ok {
			t.Fatalf("stored hash: %v, %v", ok, err)
		}
		n := len(fe.Requests())
		if _, err := db.Login(ctx, conn, "new@b.test", "long enough pw"); err != nil {
			t.Fatal(err)
		}
		if len(fe.Requests()) != n {
			t.Fatal("login after signup ran a script")
		}
	})
	t.Run("no get_user script", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, fe := importConn(t, memory.New(), s.funcs())
		delete(conn.CustomScripts, store.ScriptGetUser)
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); err != nil {
			t.Fatal(err)
		}
		if n := len(fe.Requests()); n != 0 {
			t.Fatalf("script calls = %d", n)
		}
	})
	t.Run("local user exists", func(t *testing.T) {
		s := &signupScripts{users: map[string]*legacyUser{}}
		db, conn, _ := importConn(t, memory.New(), s.funcs())
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("get_user fails", func(t *testing.T) {
		db, conn, _ := importConn(t, memory.New(), scripts{store.ScriptGetUser: func([]any) (any, error) { return nil, customdb.ErrTimeout }})
		if _, err := db.Signup(ctx, conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.Is(err, ErrScriptUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestImportResetMigrates(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "alice@legacy.test", "name": "Alice"}}}
	f := scripts{
		store.ScriptLogin: checkLogin(users),
		store.ScriptGetUser: func(args []any) (any, error) {
			if u := users[args[0].(string)]; u != nil {
				return u.profile, nil
			}
			return nil, nil
		},
	}
	db, conn, fe := importConn(t, memory.New(), f)
	ctx := context.Background()
	if _, err := db.FindForReset(ctx, conn, "nobody@legacy.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	u, err := db.FindForReset(ctx, conn, " Alice@Legacy.test")
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "auth0|42" || u.Name != "Alice" || passwordHashOf(t, db, conn, "auth0|42") != "" {
		t.Fatalf("user = %+v", u)
	}
	// A second lookup finds the local user.
	if u, err := db.FindForReset(ctx, conn, "alice@legacy.test"); err != nil || u.UserID != "auth0|42" {
		t.Fatalf("second lookup = %+v, %v", u, err)
	}
	if n := scriptCalls(fe, store.ScriptGetUser); n != 2 {
		t.Fatalf("get_user calls = %d, want 2", n)
	}
	// Before the reset completes, the login script still decides.
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if passwordHashOf(t, db, conn, "auth0|42") != "" {
		t.Fatal("a wrong password stored a hash")
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); err != nil {
		t.Fatal(err)
	}
	if ok, err := secrets.Verify(passwordHashOf(t, db, conn, "auth0|42"), "legacy pw"); err != nil || !ok {
		t.Fatalf("stored hash: %v, %v", ok, err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); err != nil {
		t.Fatal(err)
	}
	if n := scriptCalls(fe, store.ScriptLogin); n != 2 {
		t.Fatalf("login calls = %d, want 2", n)
	}
}

// A user created by a reset lookup is not taken over by a login script
// that returns another user_id for the same login.
func TestImportResetUserCollision(t *testing.T) {
	db, conn, _ := importConn(t, memory.New(), scripts{
		store.ScriptGetUser: func([]any) (any, error) { return map[string]any{"user_id": "42", "email": "alice@legacy.test"}, nil },
		store.ScriptLogin:   func([]any) (any, error) { return map[string]any{"user_id": "43", "email": "alice@legacy.test"}, nil },
	})
	ctx := context.Background()
	if _, err := db.FindForReset(ctx, conn, "alice@legacy.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "pw"); !ScriptRaised(err) {
		t.Fatalf("err = %v", err)
	}
	if passwordHashOf(t, db, conn, "auth0|42") != "" {
		t.Fatal("hash stored on a collision")
	}
	if _, err := db.Store.Users().Get(ctx, "ten_a", "auth0|43"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("colliding user created: %v", err)
	}
}

// A seeded user (stored with a hash, as seed.Apply does) is local from the
// start: no script runs, even without a script client.
func TestImportSeededUserIsLocal(t *testing.T) {
	db, conn, fe := importConn(t, memory.New(), scripts{})
	ctx := context.Background()
	hash, err := secrets.Hash("seeded pw 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Store.Users().Create(ctx, &store.User{TenantID: "ten_a", UserID: "auth0|seed1", Email: "seed@b.test",
		Identities: []store.Identity{{Connection: "Legacy", Provider: "auth0", UserID: "seed1", PasswordHash: hash}}}); err != nil {
		t.Fatal(err)
	}
	if u, err := db.Login(ctx, conn, "seed@b.test", "seeded pw 1"); err != nil || u.UserID != "auth0|seed1" {
		t.Fatalf("login = %+v, %v", u, err)
	}
	if _, err := db.Login(ctx, conn, "seed@b.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if u, err := db.FindForReset(ctx, conn, "seed@b.test"); err != nil || u.UserID != "auth0|seed1" {
		t.Fatalf("FindForReset = %+v, %v", u, err)
	}
	if n := len(fe.Requests()); n != 0 {
		t.Fatalf("script calls = %d", n)
	}
}

// A blocked user is refused after the password is checked, whether the
// script or the local hash checks it.
func TestImportBlocked(t *testing.T) {
	users := map[string]*legacyUser{"alice@legacy.test": {"legacy pw", map[string]any{"user_id": "42", "email": "alice@legacy.test"}}}
	f := scripts{
		store.ScriptLogin:   checkLogin(users),
		store.ScriptGetUser: func([]any) (any, error) { return users["alice@legacy.test"].profile, nil },
	}
	db, conn, _ := importConn(t, memory.New(), f)
	ctx := context.Background()
	u, err := db.FindForReset(ctx, conn, "alice@legacy.test")
	if err != nil {
		t.Fatal(err)
	}
	u.Blocked = true
	if err := db.Store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("via script = %v", err)
	}
	if _, err := db.Login(ctx, conn, "alice@legacy.test", "legacy pw"); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("via hash = %v", err)
	}
}
