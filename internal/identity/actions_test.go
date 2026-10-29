package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Signup must apply effects before inserting, and enqueue through that same transaction.
func TestSignupPreRegistration(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	called := false
	callbacks := SignupActions{Run: func(ctx context.Context, u *store.User) (*actionresult.Result, error) {
		called = true
		if u.Email != "new@example.com" {
			t.Fatalf("prospective email %q", u.Email)
		}
		return &actionresult.Result{Effects: actionresult.Effects{UserMetadata: map[string]any{"plan": "pro"}, AppMetadata: map[string]any{"tier": "paid"}}}, nil
	}, Enqueue: func(ctx context.Context, tx store.Store, u *store.User) error {
		saved, err := tx.Users().Get(ctx, conn.TenantID, u.UserID)
		if err != nil || saved.AppMetadata["tier"] != "paid" {
			t.Fatalf("transaction user %v %v", saved, err)
		}
		return nil
	}}
	u, err := db.Signup(ctx, conn, SignupInput{Email: "NEW@example.com", Password: "correct horse", Actions: callbacks})
	if err != nil || !called || u.UserMetadata["plan"] != "pro" {
		t.Fatalf("signup %+v %v called=%t", u, err, called)
	}
	_, err = db.Signup(ctx, conn, SignupInput{Email: "new@example.com", Password: "correct horse", Actions: callbacks})
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate %v", err)
	}
	callbacks.Run = func(context.Context, *store.User) (*actionresult.Result, error) {
		return &actionresult.Result{Denied: &actionresult.Denial{Code: "extensibility_error", UserMessage: "Refusé"}}, nil
	}
	_, err = db.Signup(ctx, conn, SignupInput{Email: "deny@example.com", Password: "correct horse", Actions: callbacks})
	var denied *ErrSignupDenied
	if !errors.As(err, &denied) || denied.Description != "Refusé" {
		t.Fatalf("denied %v", err)
	}
	if _, err = db.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, "deny@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("denied user %v", err)
	}
}

// Dropped post jobs must preserve signup success, including a full pending queue.
func TestSignupPostRegistration(t *testing.T) {
	db, conn := newDB(t)
	u, err := db.Signup(context.Background(), conn, SignupInput{Email: "ok@example.com", Password: "correct horse", Actions: SignupActions{Enqueue: func(context.Context, store.Store, *store.User) error { return store.ErrPrecondition }}})
	if err != nil || u == nil {
		t.Fatalf("queue cap lost signup: %v %v", u, err)
	}
}

// A legacy signup whose user_id already has a local record must adopt it,
// as before Actions, rather than answer user_exists after create succeeded.
func TestSignupPreRegistrationLegacyExistingLocal(t *testing.T) {
	ctx := context.Background()
	s := &signupScripts{users: map[string]*legacyUser{}}
	db, conn, _ := legacyConn(t, s.funcs())
	stale := db.profileUser(conn, &customdb.Profile{UserID: "99", Email: "new@b.test"})
	if err := db.Store.Users().Create(ctx, stale); err != nil {
		t.Fatal(err)
	}
	enqueued := 0
	callbacks := SignupActions{
		Run: func(context.Context, *store.User) (*actionresult.Result, error) { return &actionresult.Result{}, nil },
		Enqueue: func(context.Context, store.Store, *store.User) error {
			enqueued++
			return nil
		},
	}
	u, err := db.Signup(ctx, conn, SignupInput{Email: "new@b.test", Password: "long enough pw", Actions: callbacks})
	if err != nil || u.UserID != "auth0|99" || enqueued != 1 {
		t.Fatalf("signup %+v %v enqueued=%d", u, err, enqueued)
	}
}
