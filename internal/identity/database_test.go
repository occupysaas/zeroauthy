package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

func newDB(t *testing.T) (*Database, *store.Connection) {
	t.Helper()
	st := memory.New()
	conn := &store.Connection{TenantID: "ten_a", ID: "con1", Name: "Database", Strategy: store.StrategyDatabase}
	if err := st.Connections().Create(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	return &Database{Store: st, Now: fixedNow}, conn
}

func TestSignupThenLogin(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)

	u, err := db.Signup(ctx, conn, SignupInput{Email: " Alice@Example.COM ", Username: "", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "alice@example.com" || u.EmailVerified || u.Nickname != "alice" || u.Name != "alice@example.com" {
		t.Fatalf("user = %+v", u)
	}
	if len(u.UserID) != len("auth0|")+24 || u.UserID[:6] != "auth0|" {
		t.Fatalf("user_id = %q", u.UserID)
	}
	if id := u.Identities; len(id) != 1 || id[0].Connection != "Database" || id[0].Provider != "auth0" || "auth0|"+id[0].UserID != u.UserID {
		t.Fatalf("identities = %+v", id)
	}
	if ok, _ := secrets.Verify(u.Identities[0].PasswordHash, "correct horse"); !ok {
		t.Fatal("password hash does not verify")
	}

	// Review focus 4: case and whitespace insensitive login.
	got, err := db.Login(ctx, conn, "  ALICE@example.com", "correct horse")
	if err != nil || got.UserID != u.UserID {
		t.Fatalf("Login = %v, %v", got, err)
	}

	_, err = db.Signup(ctx, conn, SignupInput{Email: "alice@EXAMPLE.com", Username: "", Password: "another pass"})
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate signup err = %v, want ErrUserExists", err)
	}
}

func TestLoginFailures(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u, err := db.Signup(ctx, conn, SignupInput{Email: "bob@example.com", Username: "", Password: "bobs password"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Login(ctx, conn, "bob@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v", err)
	}
	if _, err := db.Login(ctx, conn, "bob@example.com", strings.Repeat("x", MaxPasswordBytes+1)); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("over-long password err = %v", err)
	}
	if _, err := db.Login(ctx, conn, "nobody@example.com", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v", err)
	}
	other := &store.Connection{TenantID: "ten_a", ID: "con2", Name: "Other", Strategy: store.StrategyDatabase}
	if _, err := db.Login(ctx, other, "bob@example.com", "bobs password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong connection err = %v", err)
	}

	u.Blocked = true
	if err := db.Store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "bob@example.com", "bobs password"); !errors.Is(err, ErrUserBlocked) {
		t.Errorf("blocked err = %v", err)
	}
	// A blocked user with a wrong password must not learn it is blocked.
	if _, err := db.Login(ctx, conn, "bob@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("blocked+wrong err = %v", err)
	}
}

func TestSignupRules(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)

	conn.PasswordPolicy = store.PasswordPolicy{MinLength: 10}
	var pe *PolicyError
	if _, err := db.Signup(ctx, conn, SignupInput{Email: "c@example.com", Username: "", Password: "short"}); !errors.As(err, &pe) {
		t.Errorf("weak password err = %v", err)
	}
	for _, bad := range []string{"", "not-an-email", "a@", "Name <x@example.com>"} {
		if _, err := db.Signup(ctx, conn, SignupInput{Email: bad, Password: "long enough pw"}); !errors.As(err, &pe) {
			t.Errorf("email %q err = %v", bad, err)
		}
	}

	conn.RequiresUsername = true
	if _, err := db.Signup(ctx, conn, SignupInput{Email: "d@example.com", Username: "", Password: "long enough pw"}); !errors.As(err, &pe) {
		t.Errorf("missing username err = %v", err)
	}
	u, err := db.Signup(ctx, conn, SignupInput{Email: "d@example.com", Username: " Dave_1 ", Password: "long enough pw"})
	if err != nil || u.Username != "dave_1" {
		t.Fatalf("signup with username = %+v, %v", u, err)
	}
	if got, err := db.Login(ctx, conn, "DAVE_1", "long enough pw"); err != nil || got.UserID != u.UserID {
		t.Fatalf("login by username = %v, %v", got, err)
	}

	conn.DisableSignup = true
	if _, err := db.Signup(ctx, conn, SignupInput{Email: "e@example.com", Username: "eve", Password: "long enough pw"}); !errors.Is(err, ErrSignupDisabled) {
		t.Errorf("disabled signup err = %v", err)
	}
}

func TestSignupProfile(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u, err := db.Signup(ctx, conn, SignupInput{
		Email: "p@example.com", Password: "long enough pw", GivenName: "Pat", FamilyName: "Lee",
		Name: "Pat Lee", Nickname: "patty", Picture: "https://img.example.com/p.png",
		UserMetadata: map[string]any{"plan": "pro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.GivenName != "Pat" || u.FamilyName != "Lee" || u.Name != "Pat Lee" || u.Nickname != "patty" ||
		u.Picture != "https://img.example.com/p.png" || u.UserMetadata["plan"] != "pro" {
		t.Fatalf("user = %+v", u)
	}
	d, err := db.Signup(ctx, conn, SignupInput{Email: "q@example.com", Password: "long enough pw"})
	if err != nil || d.Name != "q@example.com" || d.Nickname != "q" {
		t.Fatalf("defaults = %+v, %v", d, err)
	}
}

func TestSignupProfileRejected(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	long := strings.Repeat("x", 301)
	cases := map[string]SignupInput{
		"http picture":     {Picture: "http://img.example.com/p.png"},
		"relative picture": {Picture: "/p.png"},
		"hostless picture": {Picture: "https:///p.png"},
		"long picture":     {Picture: "https://example.com/" + strings.Repeat("a", 2000)},
		"long given_name":  {GivenName: long},
		"long family_name": {FamilyName: long},
		"long name":        {Name: long},
		"long nickname":    {Nickname: long},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			in.Email, in.Password = "r@example.com", "long enough pw"
			var pe *PolicyError
			if _, err := db.Signup(ctx, conn, in); !errors.As(err, &pe) {
				t.Fatalf("err = %v, want PolicyError", err)
			}
		})
	}
	var pe *PolicyError
	_, err := db.Signup(ctx, conn, SignupInput{Email: "r@example.com", Password: "long enough pw", Picture: "http://x.test/p"})
	if !errors.As(err, &pe) || pe.Reason != "picture must be an https URL" {
		t.Fatalf("err = %v", err)
	}
}

// Email addresses are capped at MaxEmailLength bytes (D-0020): longer ones
// are a policy error at signup and never match at login.
func TestEmailLengthCap(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	atCap := strings.Repeat("a", 64) + "@" + strings.Repeat("b", MaxEmailLength-64-1-len(".test")) + ".test"
	if len(atCap) != MaxEmailLength {
		t.Fatalf("test address is %d bytes", len(atCap))
	}
	if _, err := db.Signup(ctx, conn, SignupInput{Email: atCap, Password: "long enough pw"}); err != nil {
		t.Fatalf("signup at the cap: %v", err)
	}
	over := "c" + atCap
	var pe *PolicyError
	if _, err := db.Signup(ctx, conn, SignupInput{Email: over, Password: "long enough pw"}); !errors.As(err, &pe) {
		t.Fatalf("signup over the cap: err = %v, want PolicyError", err)
	}
	if _, err := db.Login(ctx, conn, over, "long enough pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("login over the cap: err = %v", err)
	}
	if _, err := db.Login(ctx, conn, atCap, "long enough pw"); err != nil {
		t.Errorf("login at the cap: %v", err)
	}
}
