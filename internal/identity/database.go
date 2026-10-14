package identity

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.+-]{1,64}$`)

// dummyHash is verified when a login names an unknown user, so that the
// response time does not reveal whether the user exists.
var dummyHash = sync.OnceValue(func() string {
	h, err := secrets.Hash("zeroauthy timing equalizer")
	if err != nil {
		panic(err)
	}
	return h
})

// Database authenticates users stored by zeroauthy (strategy "auth0").
type Database struct {
	Store store.Store
	Now   func() time.Time
}

func (d *Database) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Login checks a login (email or username) and password against a
// database connection. It returns ErrInvalidCredentials for unknown users
// and wrong passwords alike, and ErrUserBlocked only after the password
// has been verified.
func (d *Database) Login(ctx context.Context, conn *store.Connection, login, password string) (*store.User, error) {
	if len(password) > maxPasswordBytes {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	u, err := d.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, NormalizeLogin(login))
	if errors.Is(err, store.ErrNotFound) {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	hash := ""
	for _, id := range u.Identities {
		if id.Connection == conn.Name {
			hash = id.PasswordHash
		}
	}
	if hash == "" {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	ok, err := secrets.Verify(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// Signup registers a user on a database connection.
func (d *Database) Signup(ctx context.Context, conn *store.Connection, email, username, password string) (*store.User, error) {
	if conn.DisableSignup {
		return nil, ErrSignupDisabled
	}
	email = NormalizeLogin(email)
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || addr.Name != "" {
		return nil, &PolicyError{Reason: "enter a valid email address"}
	}
	username = NormalizeLogin(username)
	if conn.RequiresUsername {
		if !usernamePattern.MatchString(username) {
			return nil, &PolicyError{Reason: "username must be 1-64 characters: letters, digits, and _ . + -"}
		}
	} else {
		username = ""
	}
	if err := CheckPassword(conn.PasswordPolicy, password); err != nil {
		return nil, err
	}
	hash, err := secrets.Hash(password)
	if err != nil {
		return nil, err
	}
	id := secrets.RandomHex(12)
	now := d.now().UTC()
	u := &store.User{
		TenantID: conn.TenantID,
		UserID:   store.StrategyDatabase + "|" + id,
		Email:    email,
		Username: username,
		Name:     email,
		Nickname: strings.SplitN(email, "@", 2)[0],
		Identities: []store.Identity{{
			Connection: conn.Name, Provider: store.StrategyDatabase, UserID: id, PasswordHash: hash,
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := d.Store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrUserExists
		}
		return nil, err
	}
	return u, nil
}
