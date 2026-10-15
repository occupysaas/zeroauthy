package identity

import (
	"context"
	"errors"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.+-]{1,64}$`)

// CheckUsername validates a normalized username. Usernames never contain
// '@', so a login that contains one can only be an email.
func CheckUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return &PolicyError{Reason: "username must be 1-64 characters: letters, digits, and _ . + -", Key: i18n.KeyInvalidUsername}
	}
	return nil
}

// MaxEmailLength caps email addresses in bytes (RFC 5321's 254-octet path
// limit). Auth0 documents no limit; the cap keeps every storage driver in
// agreement (MySQL stores logins in VARCHAR(255)). See D-0020.
const MaxEmailLength = 254

// CheckEmail validates a normalized email address: a bare addr-spec of at
// most MaxEmailLength bytes.
func CheckEmail(email string) error {
	if len(email) > MaxEmailLength {
		return &PolicyError{Reason: "enter a valid email address"}
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || addr.Name != "" {
		return &PolicyError{Reason: "enter a valid email address"}
	}
	return nil
}

// maxLoginLength is the longest login that can match a user: an email
// (usernames are at most 64 characters).
const maxLoginLength = MaxEmailLength

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
	login = NormalizeLogin(login)
	// An over-long login matches no user; it is not sent to the store.
	if len(password) > maxPasswordBytes || len(login) > maxLoginLength {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	u, err := d.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, login)
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

// SignupInput is the data a new database-connection user signs up with.
// Name defaults to the email and Nickname to the part of the email before
// the '@'. UserMetadata is stored as given; callers validate its shape.
type SignupInput struct {
	Email, Username, Password             string
	GivenName, FamilyName, Name, Nickname string
	Picture                               string
	UserMetadata                          map[string]any
}

const (
	maxProfileFieldRunes = 300
	maxPictureLength     = 2000
)

// checkProfile validates the optional profile fields of a signup.
func checkProfile(in SignupInput) error {
	for _, f := range []struct{ label, value string }{
		{"given_name", in.GivenName}, {"family_name", in.FamilyName}, {"name", in.Name}, {"nickname", in.Nickname},
	} {
		if utf8.RuneCountInString(f.value) > maxProfileFieldRunes {
			return &PolicyError{Reason: f.label + " must be at most 300 characters"}
		}
	}
	if in.Picture != "" {
		u, err := url.Parse(in.Picture)
		if err != nil || utf8.RuneCountInString(in.Picture) > maxPictureLength || u.Scheme != "https" || u.Host == "" {
			return &PolicyError{Reason: "picture must be an https URL"}
		}
	}
	return nil
}

// Signup registers a user on a database connection.
func (d *Database) Signup(ctx context.Context, conn *store.Connection, in SignupInput) (*store.User, error) {
	if conn.DisableSignup {
		return nil, ErrSignupDisabled
	}
	username, password := in.Username, in.Password
	email := NormalizeLogin(in.Email)
	if err := CheckEmail(email); err != nil {
		return nil, err
	}
	username = NormalizeLogin(username)
	if conn.RequiresUsername {
		if err := CheckUsername(username); err != nil {
			return nil, err
		}
	} else {
		username = ""
	}
	if err := checkProfile(in); err != nil {
		return nil, err
	}
	if err := CheckPassword(conn.PasswordPolicy, password); err != nil {
		return nil, err
	}
	name, nickname := in.Name, in.Nickname
	if name == "" {
		name = email
	}
	if nickname == "" {
		nickname = strings.SplitN(email, "@", 2)[0]
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
		Name:     name,
		Nickname: nickname,

		GivenName:    in.GivenName,
		FamilyName:   in.FamilyName,
		Picture:      in.Picture,
		UserMetadata: in.UserMetadata,
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
