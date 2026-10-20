package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// CheckUsername validates a normalized username. Usernames never contain
// '@', so a login that contains one can only be an email. A connection's
// UsernameMin and UsernameMax, when set, narrow the length further.
func CheckUsername(c *store.Connection, username string) error {
	if !loginid.ValidUsername(username) {
		return &PolicyError{Reason: "username must be 1-64 characters: letters, digits, and _ . + -", Key: i18n.KeyInvalidUsername}
	}
	n := utf8.RuneCountInString(username)
	if c.UsernameMin > 0 && n < c.UsernameMin {
		return &PolicyError{
			Reason: fmt.Sprintf("username must be at least %d characters", c.UsernameMin),
			Key:    i18n.KeyUsernameTooShort, Vars: []string{"min", strconv.Itoa(c.UsernameMin)},
		}
	}
	if c.UsernameMax > 0 && n > c.UsernameMax {
		return &PolicyError{
			Reason: fmt.Sprintf("username must be at most %d characters", c.UsernameMax),
			Key:    i18n.KeyUsernameTooLong, Vars: []string{"max", strconv.Itoa(c.UsernameMax)},
		}
	}
	return nil
}

// MaxEmailLength caps email addresses in bytes (RFC 5321's 254-octet path
// limit). Auth0 documents no limit; the cap keeps every storage driver in
// agreement (MySQL stores logins in VARCHAR(255)). See D-0020.
const MaxEmailLength = loginid.MaxEmailLength

// CheckEmail validates a normalized email address: a bare addr-spec of at
// most MaxEmailLength bytes.
func CheckEmail(email string) error {
	if !loginid.ValidEmail(email) {
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

// Database authenticates users of database connections (strategy
// "auth0"): users stored by zeroauthy, or, on a customized connection,
// users of a legacy store reached through custom database scripts.
type Database struct {
	Store store.Store
	// Scripts runs custom database scripts. When nil, customized
	// connections fail with ErrScript.
	Scripts *customdb.Client
	Log     *slog.Logger
	Now     func() time.Time
}

func (d *Database) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
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
//
// On a connection in import mode, a user without a password hash (unknown,
// or created by a reset lookup) is checked by the login script and
// migrated; every other user is checked locally.
func (d *Database) Login(ctx context.Context, conn *store.Connection, login, password string) (*store.User, error) {
	password = EffectivePassword(conn, password)
	if IsLegacy(conn) {
		return d.customLogin(ctx, conn, login, password)
	}
	norm := NormalizeLogin(login)
	// An over-long login matches no user; it is not sent to the store.
	if len(password) > MaxPasswordBytes || len(norm) > maxLoginLength {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	u, err := d.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, norm)
	if errors.Is(err, store.ErrNotFound) {
		u = nil
	} else if err != nil {
		return nil, err
	}
	hash := passwordHash(u, conn.Name)
	if hash == "" && IsCustom(conn) {
		return d.importLogin(ctx, conn, strings.TrimSpace(login), password, u)
	}
	return verifyLocal(u, hash, password)
}

// passwordHash returns the password hash of u's identity on connection, or
// "" when u is nil or has none.
func passwordHash(u *store.User, connection string) string {
	if u == nil {
		return ""
	}
	hash := ""
	for _, id := range u.Identities {
		if id.Connection == connection {
			hash = id.PasswordHash
		}
	}
	return hash
}

// verifyLocal checks password against hash, the stored hash of u. An empty
// hash (no user, or no password) costs a dummy verification, so the time
// taken does not reveal whether the user exists.
func verifyLocal(u *store.User, hash, password string) (*store.User, error) {
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
// ClientID is the application signing up, passed to a create script.
type SignupInput struct {
	ClientID                              string
	Email, Username, Password             string
	GivenName, FamilyName, Name, Nickname string
	Picture                               string
	UserMetadata                          map[string]any
}

const maxProfileFieldRunes = loginid.MaxProfileFieldRunes

// checkProfile validates the optional profile fields of a signup.
func checkProfile(in SignupInput) error {
	return CheckProfile(in.GivenName, in.FamilyName, in.Name, in.Nickname, in.Picture)
}

// CheckProfile validates the optional profile fields of a new or changed
// user: the four names and the picture. userrules shares it with signup.
func CheckProfile(givenName, familyName, name, nickname, picture string) error {
	for _, f := range []struct{ label, value string }{
		{"given_name", givenName}, {"family_name", familyName}, {"name", name}, {"nickname", nickname},
	} {
		if utf8.RuneCountInString(f.value) > maxProfileFieldRunes {
			return &PolicyError{Reason: f.label + " must be at most 300 characters"}
		}
	}
	if picture != "" && !loginid.ValidPicture(picture) {
		return &PolicyError{Reason: "picture must be an https URL"}
	}
	return nil
}

// checkSignup validates a signup and returns the normalized email and
// username (empty unless the connection requires one).
func checkSignup(conn *store.Connection, in SignupInput) (email, username string, err error) {
	email = NormalizeLogin(in.Email)
	if err := CheckEmail(email); err != nil {
		return "", "", err
	}
	username = NormalizeLogin(in.Username)
	if conn.RequiresUsername {
		if err := CheckUsername(conn, username); err != nil {
			return "", "", err
		}
	} else {
		username = ""
	}
	if err := checkProfile(in); err != nil {
		return "", "", err
	}
	if err := CheckMetadata("user_metadata", in.UserMetadata); err != nil {
		return "", "", err
	}
	person := Person{
		Email: email, Username: username, Name: in.Name, GivenName: in.GivenName,
		FamilyName: in.FamilyName, Nickname: in.Nickname, UserMetadata: in.UserMetadata,
	}
	// A new user has no history. The names a signup leaves out default as
	// they do when the user is stored, so the rule sees what will be held.
	person.Name, person.Nickname = DefaultNames(in.Name, in.Nickname, email, username)
	if err := CheckPassword(conn, person, in.Password, nil); err != nil {
		return "", "", err
	}
	return email, username, nil
}

// DefaultNames fills an empty name with the email and an empty nickname
// with the part of the email before the '@'. Without an email (a legacy
// profile may have only a username) both default to the username.
func DefaultNames(name, nickname, email, username string) (string, string) {
	if name == "" {
		name = email
		if name == "" {
			name = username
		}
	}
	if nickname == "" {
		nickname = strings.SplitN(email, "@", 2)[0]
		if nickname == "" {
			nickname = username
		}
	}
	return name, nickname
}

// Signup registers a user on a database connection.
func (d *Database) Signup(ctx context.Context, conn *store.Connection, in SignupInput) (*store.User, error) {
	if conn.DisableSignup {
		return nil, ErrSignupDisabled
	}
	if IsLegacy(conn) {
		return d.customSignup(ctx, conn, in)
	}
	email, username, err := checkSignup(conn, in)
	if err != nil {
		return nil, err
	}
	if IsCustom(conn) {
		if err := d.importSignupCheck(ctx, conn, email, username); err != nil {
			return nil, err
		}
	}
	name, nickname := DefaultNames(in.Name, in.Nickname, email, username)
	hash, err := secrets.Hash(EffectivePassword(conn, in.Password))
	if err != nil {
		return nil, err
	}
	picture := in.Picture
	if picture == "" {
		picture = DefaultPicture(email)
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
		Picture:      picture,
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
	if err := RecordPassword(ctx, d.Store, conn, u.UserID, hash); err != nil {
		return nil, err
	}
	return u, nil
}

// FindForReset returns the user of conn whose email address is email, for
// a password reset. It returns store.ErrNotFound for an unknown address.
// Logins also match usernames; a reset names an address, so a username
// match is reported as store.ErrNotFound. On a legacy connection the
// get_user script decides, and the local record is created or updated. In
// import mode a local user wins; otherwise a user the get_user script
// knows is migrated without a password.
func (d *Database) FindForReset(ctx context.Context, conn *store.Connection, email string) (*store.User, error) {
	email = NormalizeLogin(email)
	if IsLegacy(conn) {
		return d.legacyFindForReset(ctx, conn, email)
	}
	if len(email) > MaxEmailLength {
		return nil, store.ErrNotFound // no user can have it; not sent to the store
	}
	user, err := d.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, email)
	if errors.Is(err, store.ErrNotFound) && IsCustom(conn) {
		return d.importFindForReset(ctx, conn, email)
	}
	if err != nil {
		return nil, err
	}
	if user.Email != email {
		return nil, store.ErrNotFound
	}
	return user, nil
}
