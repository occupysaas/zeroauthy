package customdb

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testWrapper(t *testing.T) keys.Wrapper {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	w, err := keys.NewLocalWrapper(key)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// clientFor returns a Client whose scripts are funcs, and a connection with
// a non-empty source for each of them.
func clientFor(t *testing.T, funcs map[string]func([]any) (any, error)) (*Client, *FuncExecutor, *store.Connection) {
	t.Helper()
	fe := &FuncExecutor{Funcs: funcs}
	conn := &store.Connection{TenantID: "ten_a", ID: "con_1", Name: "Legacy", Strategy: store.StrategyDatabase,
		EnabledDatabaseCustomization: true, CustomScripts: map[string]string{}}
	for name := range funcs {
		conn.CustomScripts[name] = "function " + name + "() {}"
	}
	return &Client{Exec: fe, Wrapper: testWrapper(t)}, fe, conn
}

func loginReturning(v any) map[string]func([]any) (any, error) {
	return map[string]func([]any) (any, error){
		store.ScriptLogin: func([]any) (any, error) { return v, nil },
	}
}

func TestLoginDecodesProfile(t *testing.T) {
	c, fe, conn := clientFor(t, loginReturning(map[string]any{
		"user_id": 42, "email": "Alice@Example.COM", "email_verified": true, "name": "Alice",
		"app_metadata": map[string]any{"plan": "gold"},
	}))
	p, err := c.Login(context.Background(), conn, "alice@example.com", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "42" || p.Email != "alice@example.com" || !p.EmailVerified || p.Name != "Alice" || p.AppMetadata["plan"] != "gold" {
		t.Fatalf("profile = %+v", p)
	}
	reqs := fe.Requests()
	if len(reqs) != 1 || reqs[0].Script != store.ScriptLogin || reqs[0].TenantID != "ten_a" || reqs[0].ConnectionID != "con_1" ||
		reqs[0].Source != conn.CustomScripts[store.ScriptLogin] || len(reqs[0].Args) != 2 || reqs[0].Args[0] != "alice@example.com" || reqs[0].Args[1] != "pw" {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestLoginRejectsBadProfile(t *testing.T) {
	long := strings.Repeat("x", 201)
	for _, tc := range []struct {
		name    string
		profile any
		secret  string // must not appear in the error
	}{
		{"no user_id", map[string]any{"email": "a@b.test"}, ""},
		{"empty user_id", map[string]any{"user_id": "", "email": "a@b.test"}, ""},
		{"fractional user_id", map[string]any{"user_id": 1.5, "email": "a@b.test"}, "1.5"},
		{"pipe in user_id", map[string]any{"user_id": "a|b", "email": "a@b.test"}, "a|b"},
		{"long user_id", map[string]any{"user_id": long, "email": "a@b.test"}, long},
		{"bad email", map[string]any{"user_id": "1", "email": "not-an-email"}, "not-an-email"},
		{"no email or username", map[string]any{"user_id": "1", "name": "Nobody"}, ""},
		{"array metadata", map[string]any{"user_id": "1", "email": "a@b.test", "user_metadata": []any{"secretvalue"}}, "secretvalue"},
		{"http picture", map[string]any{"user_id": "1", "email": "a@b.test", "picture": "http://img.test/secretpic"}, "secretpic"},
		{"not an object", "just-a-string", "just-a-string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, conn := clientFor(t, loginReturning(tc.profile))
			_, err := c.Login(context.Background(), conn, "a@b.test", "pw")
			if !errors.Is(err, ErrBadProfile) {
				t.Fatalf("err = %v, want ErrBadProfile", err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("error %q quotes the bad value", err)
			}
		})
	}
}

func TestLoginPassesScriptErrors(t *testing.T) {
	se := &ScriptError{Kind: KindWrongCredentials, Message: "nope"}
	c, _, conn := clientFor(t, map[string]func([]any) (any, error){
		store.ScriptLogin: func([]any) (any, error) { return nil, se },
	})
	if _, err := c.Login(context.Background(), conn, "a@b.test", "pw"); !errors.Is(err, se) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetUserNull(t *testing.T) {
	c, fe, conn := clientFor(t, map[string]func([]any) (any, error){
		store.ScriptGetUser: func([]any) (any, error) { return nil, nil },
	})
	p, err := c.GetUser(context.Background(), conn, "a@b.test")
	if p != nil || err != nil {
		t.Fatalf("GetUser = %+v, %v", p, err)
	}
	if reqs := fe.Requests(); len(reqs) != 1 || len(reqs[0].Args) != 1 || reqs[0].Args[0] != "a@b.test" {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestChangePasswordBool(t *testing.T) {
	for _, tc := range []struct {
		result any
		want   bool
	}{
		{true, true},
		{false, false},
		{map[string]any{"last_password_reset": "2026-10-15T00:00:00Z"}, true},
	} {
		c, fe, conn := clientFor(t, map[string]func([]any) (any, error){
			store.ScriptChangePassword: func([]any) (any, error) { return tc.result, nil },
		})
		got, err := c.ChangePassword(context.Background(), conn, "a@b.test", "new pw")
		if err != nil || got != tc.want {
			t.Fatalf("ChangePassword(%v) = %v, %v", tc.result, got, err)
		}
		if reqs := fe.Requests(); len(reqs[0].Args) != 2 || reqs[0].Args[0] != "a@b.test" || reqs[0].Args[1] != "new pw" {
			t.Fatalf("args = %+v", reqs[0].Args)
		}
	}
}

func TestCreateSendsUser(t *testing.T) {
	var got map[string]any
	c, _, conn := clientFor(t, map[string]func([]any) (any, error){
		store.ScriptCreate: func(args []any) (any, error) {
			got, _ = args[0].(map[string]any)
			return nil, nil
		},
	})
	err := c.Create(context.Background(), conn, CreateUser{Tenant: "acme", ClientID: "app", Connection: "Legacy",
		Email: "a@b.test", Password: "pw", Username: "ab", UserMetadata: map[string]any{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if got["tenant"] != "acme" || got["client_id"] != "app" || got["connection"] != "Legacy" || got["email"] != "a@b.test" ||
		got["password"] != "pw" || got["username"] != "ab" || got["user_metadata"].(map[string]any)["k"] != "v" {
		t.Fatalf("create user = %v", got)
	}
}

func TestConfigOpenedPerConnection(t *testing.T) {
	c, fe, conn := clientFor(t, loginReturning(map[string]any{"user_id": "1", "email": "a@b.test"}))
	cfg := map[string]string{"DB_URL": "postgres://legacy", "API_KEY": "k"}
	sealed, err := keys.SealConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.ConfigurationSealed = sealed
	if _, err := c.Login(context.Background(), conn, "a@b.test", "pw"); err != nil {
		t.Fatal(err)
	}
	if got := fe.Requests()[0].Config; !maps.Equal(got, cfg) {
		t.Fatalf("config = %v", got)
	}
	// A blob sealed for another connection does not open.
	conn.ID = "con_2"
	if _, err := c.Login(context.Background(), conn, "a@b.test", "pw"); err == nil || strings.Contains(err.Error(), "legacy") {
		t.Fatalf("foreign config err = %v", err)
	}
}

func TestMissingScript(t *testing.T) {
	c, fe, conn := clientFor(t, loginReturning(nil))
	conn.CustomScripts[store.ScriptCreate] = ""
	err := c.Create(context.Background(), conn, CreateUser{Email: "a@b.test", Password: "pw"})
	if !errors.Is(err, ErrNoScript) {
		t.Fatalf("err = %v", err)
	}
	if len(fe.Requests()) != 0 {
		t.Fatal("Exec was called")
	}
}

func TestDeleteChangeEmailVerify(t *testing.T) {
	ctx := context.Background()
	c, fe, conn := clientFor(t, map[string]func([]any) (any, error){
		store.ScriptDelete:      func([]any) (any, error) { return nil, nil },
		store.ScriptChangeEmail: func(a []any) (any, error) { return a[2] == true, nil },
		store.ScriptVerify:      func([]any) (any, error) { return true, nil },
	})
	if err := c.Delete(ctx, conn, "42"); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.ChangeEmail(ctx, conn, "a@b.test", "c@d.test", true); err != nil || !ok {
		t.Fatalf("change email = %v, %v", ok, err)
	}
	if ok, err := c.ChangeEmail(ctx, conn, "a@b.test", "c@d.test", false); err != nil || ok {
		t.Fatalf("change email (false) = %v, %v", ok, err)
	}
	if ok, err := c.Verify(ctx, conn, "a@b.test"); err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	reqs := fe.Requests()
	if len(reqs) != 4 || reqs[0].Script != store.ScriptDelete || len(reqs[0].Args) != 1 || reqs[0].Args[0] != "42" ||
		reqs[1].Script != store.ScriptChangeEmail || len(reqs[1].Args) != 3 || reqs[1].Args[0] != "a@b.test" || reqs[1].Args[1] != "c@d.test" ||
		reqs[3].Script != store.ScriptVerify || len(reqs[3].Args) != 1 {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestChangeEmailErrors(t *testing.T) {
	ctx := context.Background()
	c, _, conn := clientFor(t, map[string]func([]any) (any, error){
		store.ScriptChangeEmail: func([]any) (any, error) { return "yes", nil },
		store.ScriptDelete:      func([]any) (any, error) { return nil, &ScriptError{Kind: KindError, Message: "boom"} },
	})
	if _, err := c.ChangeEmail(ctx, conn, "a@b.test", "c@d.test", false); err == nil {
		t.Fatal("a string result was accepted")
	}
	var se *ScriptError
	if err := c.Delete(ctx, conn, "1"); !errors.As(err, &se) || se.Message != "boom" {
		t.Fatalf("delete = %v", err)
	}
	if _, err := c.Verify(ctx, conn, "a@b.test"); !errors.Is(err, ErrNoScript) {
		t.Fatalf("verify without a script = %v", err)
	}
}
