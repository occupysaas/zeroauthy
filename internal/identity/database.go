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

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/passhash"
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
	loginCommit func(context.Context, store.Store, *store.User) error
	Store       store.Store
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
	return d.LoginWithCheck(ctx, conn, login, password, nil)
}

// LoginWithCheck runs check only after credentials have been verified. Legacy
// script profiles and first-time custom imports are not persisted until check
// succeeds. Existing imported-hash upgrades intentionally retain Login's behavior;
// check still runs before the caller may issue a session or token.
func (d *Database) LoginWithCheck(ctx context.Context, conn *store.Connection, login, password string, check func(context.Context) error) (*store.User, error) {
	password = EffectivePassword(conn, password)
	if IsLegacy(conn) {
		return d.customLogin(ctx, conn, login, password, check)
	}
	checked := false
	checkOnce := func(ctx context.Context) error {
		if check == nil || checked {
			return nil
		}
		checked = true
		return check(ctx)
	}
	u, err := d.loginLocal(ctx, conn, login, password, checkOnce)
	if err != nil {
		return nil, err
	}
	if err := checkOnce(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// LoginWithCheckAndCommit applies commit in the local user-write transaction,
// after credential and policy checks. External custom scripts run before it.
func (d *Database) LoginWithCheckAndCommit(ctx context.Context, conn *store.Connection, login, password string, check func(context.Context) error, commit func(context.Context, store.Store, *store.User) error) (*store.User, error) {
	if commit == nil {
		return d.LoginWithCheck(ctx, conn, login, password, check)
	}
	bound := *d
	committed := false
	bound.loginCommit = func(ctx context.Context, tx store.Store, u *store.User) error {
		if err := commit(ctx, tx, u); err != nil {
			return err
		}
		committed = true
		return nil
	}
	u, err := bound.LoginWithCheck(ctx, conn, login, password, check)
	if err != nil {
		return nil, err
	}
	if !committed {
		err = d.Store.WithTx(ctx, func(tx store.Store) error { return commit(ctx, tx, u) })
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}
func (d *Database) loginWrite(ctx context.Context, fn func(*Database) (*store.User, error)) (*store.User, error) {
	if d.loginCommit == nil {
		return fn(d)
	}
	var u *store.User
	err := d.Store.WithTx(ctx, func(tx store.Store) error {
		bound := *d
		bound.Store = tx
		bound.loginCommit = nil
		var err error
		u, err = fn(&bound)
		if err != nil {
			return err
		}
		return d.loginCommit(ctx, tx, u)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *Database) loginLocal(ctx context.Context, conn *store.Connection, login, password string, check func(context.Context) error) (*store.User, error) {
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
	hash, imported := credentials(u, conn.Name, norm)
	if imported != "" {
		return d.importedLogin(ctx, conn, u, norm, imported, password, true, check)
	}
	if hash == "" && IsCustom(conn) {
		return d.importLogin(ctx, conn, strings.TrimSpace(login), password, u, check)
	}
	return verifyLocal(u, hash, password)
}

// importedLogin verifies password against imported, the Auth0 import hash
// of u's identity, then replaces it with a native hash. A value that cannot
// be verified gives ErrPasswordChangeRequired for any password. The
// password policy and history are not applied (as on Auth0). When the
// upgrade finds the hash replaced meanwhile (a bulk import upserting the
// user), the user is read once more and checked against what is stored now;
// retry is false on that second pass.
func (d *Database) importedLogin(ctx context.Context, conn *store.Connection, u *store.User, login, imported, password string, retry bool, check func(context.Context) error) (*store.User, error) {
	spec, err := passhash.Unmarshal(imported)
	if err != nil {
		return nil, ErrPasswordChangeRequired
	}
	ok, err := spec.Verify(password)
	if errors.Is(err, passhash.ErrUnusable) {
		return nil, ErrPasswordChangeRequired
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		// A native failure costs an argon2 verification; so does this.
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	hash, err := secrets.Hash(password)
	if err != nil {
		return nil, err
	}
	if d.loginCommit != nil {
		if u.Blocked {
			return nil, ErrUserBlocked
		}
		if check != nil {
			if err := check(ctx); err != nil {
				return nil, err
			}
		}
	}
	return d.loginWrite(ctx, func(bound *Database) (*store.User, error) {
		return bound.persistImportedHash(ctx, conn, u, login, imported, password, hash, retry, check)
	})
}
func (d *Database) persistImportedHash(ctx context.Context, conn *store.Connection, u *store.User, login, imported, password, hash string, retry bool, check func(context.Context) error) (*store.User, error) {
	var err error
	err = d.Store.Users().UpgradeImportedHash(ctx, conn.TenantID, u.UserID, conn.Name, imported, hash, d.now().UTC())
	if errors.Is(err, store.ErrConflict) {
		fresh, gerr := d.Store.Users().Get(ctx, conn.TenantID, u.UserID)
		if errors.Is(gerr, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		if gerr != nil {
			return nil, gerr
		}
		h, imp := credentials(fresh, conn.Name, login)
		if imp != "" {
			if !retry {
				// Replaced again during the second pass: give up.
				return nil, ErrInvalidCredentials
			}
			return d.importedLogin(ctx, conn, fresh, login, imp, password, false, check)
		}
		return verifyLocal(fresh, h, password)
	}
	if err != nil {
		return nil, err
	}
	// Re-read: the caller checks the user's Version before minting.
	u, err = d.Store.Users().Get(ctx, conn.TenantID, u.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	return d.finishImported(u)
}

func (d *Database) finishImported(u *store.User) (*store.User, error) {
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// credentials returns the native password hash and the imported hash of
// the identity passwordHash would choose; at most one is non-empty.
func credentials(u *store.User, connection, login string) (hash, imported string) {
	if u == nil {
		return "", ""
	}
	id := u.IdentityByLogin(connection, login)
	if id == nil {
		for i := range u.Identities {
			if u.Identities[i].Connection == connection && !u.Identities[i].Linked() {
				id = &u.Identities[i]
				break
			}
		}
	}
	if id == nil {
		return "", ""
	}
	return id.PasswordHash, id.ImportedHash
}

// passwordHash returns the password hash of the identity of u on connection
// that login (normalized) names, or "" when u is nil or has none. A user
// can hold several identities on one connection once accounts are linked
// (D-0043), each with its own password: the identity is the one whose
// email or username is login (store.User.IdentityByLogin), never just the
// first on the connection. When no identity names login, u's own identity
// on connection is used.
func passwordHash(u *store.User, connection, login string) string {
	if u == nil {
		return ""
	}
	if id := u.IdentityByLogin(connection, login); id != nil {
		return id.PasswordHash
	}
	for _, id := range u.Identities {
		if id.Connection == connection && !id.Linked() {
			return id.PasswordHash
		}
	}
	return ""
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
	Actions                               SignupActions
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
	if err := d.runSignupActions(ctx, in.Actions, u); err != nil {
		return nil, err
	}
	if err := d.insertSignup(ctx, conn, in.Actions, u, hash); err != nil {
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

// SignupActions injects signup flows without coupling identity to the Actions runtime.
// actionresult.Result is aliased as actions.Result.
type SignupActions struct {
	Commit  func(context.Context, store.Store, *store.User) error
	Run     func(context.Context, *store.User) (*actionresult.Result, error)
	Enqueue func(context.Context, store.Store, *store.User) error
}

type ErrSignupDenied struct{ Code, Description string }

func (e *ErrSignupDenied) Error() string { return "signup denied" }

type ErrSignupActionFailed struct{ ExecutionID string }

func (e *ErrSignupActionFailed) Error() string { return "signup Action failed" }

func (d *Database) runSignupActions(ctx context.Context, a SignupActions, u *store.User) error {
	if a.Run == nil {
		return nil
	}
	result, err := a.Run(ctx, u)
	if err != nil {
		var failed *ErrSignupActionFailed
		if errors.As(err, &failed) {
			return failed
		}
		return &ErrSignupActionFailed{}
	}
	if result == nil {
		return &ErrSignupActionFailed{}
	}
	if result.Denied != nil {
		code := result.Denied.Code
		if code == "" {
			code = "extensibility_error"
		}
		message := result.Denied.UserMessage
		if message == "" {
			message = "Unable to complete signup."
		}
		return &ErrSignupDenied{Code: code, Description: message}
	}
	userMeta := mergeSignupMetadata(u.UserMetadata, result.Effects.UserMetadata)
	appMeta := mergeSignupMetadata(u.AppMetadata, result.Effects.AppMetadata)
	if CheckMetadata("user_metadata", userMeta) != nil || CheckMetadata("app_metadata", appMeta) != nil {
		return &ErrSignupActionFailed{ExecutionID: result.ExecutionID}
	}
	u.UserMetadata, u.AppMetadata = userMeta, appMeta
	return nil
}
func mergeSignupMetadata(base, patch map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(patch))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}
func (d *Database) insertSignup(ctx context.Context, conn *store.Connection, a SignupActions, u *store.User, hash string) error {
	err := d.Store.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		if hash != "" {
			if err := RecordPassword(ctx, tx, conn, u.UserID, hash); err != nil {
				return err
			}
		}
		if a.Commit != nil {
			if err := a.Commit(ctx, tx, u); err != nil {
				return err
			}
		}
		return d.enqueueSignup(ctx, tx, conn, a, u)
	})
	if errors.Is(err, store.ErrConflict) {
		return ErrUserExists
	}
	return err
}

// enqueueSignup queues post-registration in tx. A full queue drops the job
// with a log line and keeps the signup.
func (d *Database) enqueueSignup(ctx context.Context, tx store.Store, conn *store.Connection, a SignupActions, u *store.User) error {
	if a.Enqueue == nil {
		return nil
	}
	err := a.Enqueue(ctx, tx, u)
	if errors.Is(err, store.ErrPrecondition) {
		d.log().WarnContext(ctx, "post-registration Action job dropped", "tenant", conn.TenantID, "user_id", u.UserID, "error", err)
		return nil
	}
	return err
}
