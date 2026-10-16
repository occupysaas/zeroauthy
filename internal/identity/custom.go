package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// IsCustom reports whether conn runs custom database scripts.
func IsCustom(conn *store.Connection) bool { return conn.EnabledDatabaseCustomization }

// IsLegacy reports whether conn's custom database scripts are the source of
// truth (customized, not import mode).
func IsLegacy(conn *store.Connection) bool { return IsCustom(conn) && !conn.ImportMode }

// ScriptRaised reports whether err is a custom database script failure the
// script itself raised (an error it passed or threw, an invalid profile, a
// collision), as opposed to a script that could not answer. A raised
// failure counts as a failed login attempt, since legacy scripts often
// report a wrong password as a plain Error (D-0023).
func ScriptRaised(err error) bool {
	return errors.Is(err, ErrScript) && !errors.Is(err, ErrScriptUnavailable)
}

// errNoClient is a customized connection on a server built without a
// script client.
var errNoClient = errors.New("identity: custom database scripts are not configured")

// scriptErr maps a script failure. A script's UnauthorizedError becomes
// *UnauthorizedError; everything else is logged and wrapped in ErrScript,
// and also in ErrScriptUnavailable when the script gave no answer.
func (d *Database) scriptErr(ctx context.Context, conn *store.Connection, script string, err error) error {
	kind, msg := "error", err.Error()
	unavailable := true
	var se *customdb.ScriptError
	switch {
	case errors.As(err, &se):
		kind, msg = se.Kind, se.Message
		if se.Kind == customdb.KindUnauthorized {
			d.log().InfoContext(ctx, "custom database script refused the user",
				"tenant", conn.TenantID, "connection", conn.Name, "script", script, "kind", kind, "message", msg)
			return &UnauthorizedError{Message: se.Message}
		}
		unavailable = false
	case errors.Is(err, customdb.ErrTimeout):
		kind = "timeout"
	case errors.Is(err, customdb.ErrUnavailable):
		kind = "unavailable"
	case errors.Is(err, customdb.ErrNoScript):
		kind = "no_script"
	case errors.Is(err, customdb.ErrBadProfile):
		kind, unavailable = "bad_profile", false
	case errors.Is(err, customdb.ErrConfig):
		kind = "config"
	}
	d.log().ErrorContext(ctx, "custom database script failed",
		"tenant", conn.TenantID, "connection", conn.Name, "script", script, "kind", kind, "message", msg)
	if unavailable {
		return fmt.Errorf("%w: %w: %w", ErrScript, ErrScriptUnavailable, err)
	}
	return fmt.Errorf("%w: %w", ErrScript, err)
}

// scripts returns the client, or an ErrScript when there is none.
func (d *Database) scripts(ctx context.Context, conn *store.Connection, script string) (*customdb.Client, error) {
	if d.Scripts == nil {
		return nil, d.scriptErr(ctx, conn, script, errNoClient)
	}
	return d.Scripts, nil
}

// customLogin authenticates a user of a legacy connection through the login
// script. The script decides every time; the local record is never used to
// check a password.
func (d *Database) customLogin(ctx context.Context, conn *store.Connection, login, password string) (*store.User, error) {
	login = strings.TrimSpace(login)
	if len(password) > maxPasswordBytes || len(login) > maxLoginLength {
		return nil, ErrInvalidCredentials
	}
	c, err := d.scripts(ctx, conn, store.ScriptLogin)
	if err != nil {
		return nil, err
	}
	p, err := d.runLogin(ctx, conn, c, login, password)
	if err != nil {
		return nil, err
	}
	u, err := d.upsertProfile(ctx, conn, p, true)
	if err != nil {
		return nil, err
	}
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// runLogin runs the login script. A WrongUsernameOrPasswordError is
// ErrInvalidCredentials; other failures go through scriptErr.
func (d *Database) runLogin(ctx context.Context, conn *store.Connection, c *customdb.Client, login, password string) (*customdb.Profile, error) {
	p, err := c.Login(ctx, conn, login, password)
	if err != nil {
		var se *customdb.ScriptError
		if errors.As(err, &se) && se.Kind == customdb.KindWrongCredentials {
			return nil, ErrInvalidCredentials
		}
		return nil, d.scriptErr(ctx, conn, store.ScriptLogin, err)
	}
	return p, nil
}

// importLogin authenticates a user of an import-mode connection who has no
// local password yet: u is the local user without a hash (created by a
// reset lookup), or nil. The login script checks the password, and on
// success the user is stored, or completed, with a hash of it, so later
// logins are checked locally.
func (d *Database) importLogin(ctx context.Context, conn *store.Connection, login, password string, u *store.User) (*store.User, error) {
	c, err := d.scripts(ctx, conn, store.ScriptLogin)
	if err != nil {
		return nil, err
	}
	p, err := d.runLogin(ctx, conn, c, login, password)
	if err != nil {
		return nil, err
	}
	hash, err := secrets.Hash(password)
	if err != nil {
		return nil, err
	}
	if u == nil {
		var created bool
		u, created, err = d.createImported(ctx, conn, p, hash)
		if err != nil {
			return nil, err
		}
		if created {
			return u, nil
		}
		// A concurrent first login migrated the user first: its hash
		// decides.
		if h := passwordHash(u, conn.Name); h != "" {
			return verifyLocal(u, h, password)
		}
	}
	if u.UserID != store.StrategyDatabase+"|"+p.UserID || !onConnection(u, conn, p.UserID) {
		return nil, d.collision(ctx, conn, store.StrategyDatabase+"|"+p.UserID, "login belongs to another user")
	}
	now := d.now().UTC()
	if err := d.Store.Users().SetPasswordHash(ctx, conn.TenantID, u.UserID, conn.Name, hash, now); err != nil {
		return nil, err
	}
	for i := range u.Identities {
		if u.Identities[i].Connection == conn.Name {
			u.Identities[i].PasswordHash = hash
		}
	}
	u.UpdatedAt = now
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// importGetUser runs the get_user script of an import-mode connection.
// get_user is optional there, so a connection without one finds nobody
// (D-0023).
func (d *Database) importGetUser(ctx context.Context, conn *store.Connection, login string) (*customdb.Profile, error) {
	c, err := d.scripts(ctx, conn, store.ScriptGetUser)
	if err != nil {
		return nil, err
	}
	p, err := c.GetUser(ctx, conn, login)
	if errors.Is(err, customdb.ErrNoScript) {
		return nil, nil
	}
	if err != nil {
		return nil, d.scriptErr(ctx, conn, store.ScriptGetUser, err)
	}
	return p, nil
}

// importSignupCheck refuses a sign-up on an import-mode connection when the
// get_user script knows the email or username. The user is then created
// locally; the create script is never called.
func (d *Database) importSignupCheck(ctx context.Context, conn *store.Connection, email, username string) error {
	lookups := []string{email}
	if username != "" {
		lookups = append(lookups, username)
	}
	for _, id := range lookups {
		p, err := d.importGetUser(ctx, conn, id)
		if err != nil {
			return err
		}
		if p != nil {
			return ErrUserExists
		}
	}
	return nil
}

// importFindForReset migrates a user the get_user script knows by email,
// without a password: the reset sets it, or the next login through the
// login script does.
func (d *Database) importFindForReset(ctx context.Context, conn *store.Connection, email string) (*store.User, error) {
	if CheckEmail(email) != nil {
		return nil, store.ErrNotFound
	}
	p, err := d.importGetUser(ctx, conn, email)
	if err != nil {
		return nil, err
	}
	if p == nil || p.Email != email {
		return nil, store.ErrNotFound
	}
	u, _, err := d.createImported(ctx, conn, p, "")
	if err != nil {
		return nil, err
	}
	if u.Email != email {
		return nil, store.ErrNotFound
	}
	return u, nil
}

// createImported stores the user of profile p on an import-mode connection,
// with hash as its password hash (empty for a reset lookup). If a
// concurrent migration stored the same user first, it returns that user
// and created is false; anything else holding the user_id, email or
// username is a collision (D-0024).
func (d *Database) createImported(ctx context.Context, conn *store.Connection, p *customdb.Profile, hash string) (u *store.User, created bool, err error) {
	u = d.profileUser(conn, p)
	u.Identities[0].PasswordHash = hash
	err = d.Store.Users().Create(ctx, u)
	if err == nil {
		return u, true, nil
	}
	if !errors.Is(err, store.ErrConflict) {
		return nil, false, err
	}
	u, err = d.Store.Users().Get(ctx, conn.TenantID, u.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, d.collision(ctx, conn, store.StrategyDatabase+"|"+p.UserID, "email or username in use")
	}
	if err != nil {
		return nil, false, err
	}
	if !onConnection(u, conn, p.UserID) {
		return nil, false, d.collision(ctx, conn, u.UserID, "user_id belongs to another connection")
	}
	return u, false, nil
}

// customSignup creates the user in the legacy store, then logs in through
// the login script to confirm the account and learn its user_id.
func (d *Database) customSignup(ctx context.Context, conn *store.Connection, in SignupInput) (*store.User, error) {
	email, username, err := checkSignup(conn, in)
	if err != nil {
		return nil, err
	}
	c, err := d.scripts(ctx, conn, store.ScriptCreate)
	if err != nil {
		return nil, err
	}
	lookups := []string{email}
	if username != "" {
		lookups = append(lookups, username)
	}
	for _, id := range lookups {
		p, err := c.GetUser(ctx, conn, id)
		if err != nil {
			return nil, d.scriptErr(ctx, conn, store.ScriptGetUser, err)
		}
		if p != nil {
			return nil, ErrUserExists
		}
	}
	tn, err := d.Store.Tenants().Get(ctx, conn.TenantID)
	if err != nil {
		return nil, err
	}
	err = c.Create(ctx, conn, customdb.CreateUser{
		Tenant: tn.Name, ClientID: in.ClientID, Connection: conn.Name,
		Email: email, Password: in.Password, Username: username, UserMetadata: in.UserMetadata,
	})
	if err != nil {
		var se *customdb.ScriptError
		switch {
		case errors.As(err, &se) && se.Kind == customdb.KindValidation && se.Code == "user_exists":
			return nil, ErrUserExists
		case errors.As(err, &se) && se.Kind == customdb.KindValidation:
			return nil, &PolicyError{Reason: se.Message}
		}
		return nil, d.scriptErr(ctx, conn, store.ScriptCreate, err)
	}
	p, err := c.Login(ctx, conn, email, in.Password)
	if err != nil {
		// The account was just created, so any answer but a profile is a
		// script failure. A refusal (UnauthorizedError) keeps its message
		// for the user.
		return nil, d.scriptErr(ctx, conn, store.ScriptLogin, err)
	}
	u, err := d.upsertProfile(ctx, conn, p, true)
	if err != nil {
		return nil, err
	}
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// legacyFindForReset asks the get_user script about email. Only a profile
// whose email is email counts; a username is never sent.
func (d *Database) legacyFindForReset(ctx context.Context, conn *store.Connection, email string) (*store.User, error) {
	if CheckEmail(email) != nil {
		return nil, store.ErrNotFound
	}
	c, err := d.scripts(ctx, conn, store.ScriptGetUser)
	if err != nil {
		return nil, err
	}
	p, err := c.GetUser(ctx, conn, email)
	if err != nil {
		return nil, d.scriptErr(ctx, conn, store.ScriptGetUser, err)
	}
	if p == nil || p.Email != email {
		return nil, store.ErrNotFound
	}
	return d.upsertProfile(ctx, conn, p, false)
}

// ChangeLegacyPassword sets user's password in the legacy store through
// the change_password script.
func (d *Database) ChangeLegacyPassword(ctx context.Context, conn *store.Connection, user *store.User, newPassword string) error {
	c, err := d.scripts(ctx, conn, store.ScriptChangePassword)
	if err != nil {
		return err
	}
	ok, err := c.ChangePassword(ctx, conn, user.Email, newPassword)
	if err != nil {
		return d.scriptErr(ctx, conn, store.ScriptChangePassword, err)
	}
	if !ok {
		d.log().WarnContext(ctx, "custom database script did not change the password",
			"tenant", conn.TenantID, "connection", conn.Name, "script", store.ScriptChangePassword, "user_id", user.UserID)
		return ErrPasswordNotChanged
	}
	return nil
}

// collision logs a profile that cannot be stored without taking over
// another user's identity or login, and fails closed (D-0024).
func (d *Database) collision(ctx context.Context, conn *store.Connection, userID, why string) error {
	d.log().ErrorContext(ctx, "custom database profile collides with another user",
		"tenant", conn.TenantID, "connection", conn.Name, "user_id", userID, "reason", why)
	return fmt.Errorf("%w: profile collides with another user (%s)", ErrScript, why)
}

// upsertProfile creates or updates the local record of a legacy user
// (D-0024). onLogin also syncs the name fields and picture, unless the
// connection sets them on first login only. Metadata is set only at
// creation.
func (d *Database) upsertProfile(ctx context.Context, conn *store.Connection, p *customdb.Profile, onLogin bool) (*store.User, error) {
	userID := store.StrategyDatabase + "|" + p.UserID
	now := d.now().UTC()
	u, err := d.Store.Users().Get(ctx, conn.TenantID, userID)
	if errors.Is(err, store.ErrNotFound) {
		u = d.profileUser(conn, p)
		if err = d.Store.Users().Create(ctx, u); err == nil {
			return u, nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		// A simultaneous first login may have created the user since the
		// Get. If so, continue as an update, whose identity check still
		// catches a real collision.
		u, err = d.Store.Users().Get(ctx, conn.TenantID, userID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, d.collision(ctx, conn, userID, "email or username in use")
		}
	}
	if err != nil {
		return nil, err
	}
	if !onConnection(u, conn, p.UserID) {
		return nil, d.collision(ctx, conn, userID, "user_id belongs to another connection")
	}
	u.Email, u.Username, u.EmailVerified = p.Email, p.Username, p.EmailVerified
	if onLogin && conn.SetUserRootAttributes != store.RootAttributesOnFirstLogin {
		u.Name, u.Nickname = defaultNames(p.Name, p.Nickname, p.Email, p.Username)
		u.GivenName, u.FamilyName, u.Picture = p.GivenName, p.FamilyName, p.Picture
	}
	u.UpdatedAt = now
	if err := d.Store.Users().Update(ctx, u); errors.Is(err, store.ErrConflict) {
		return nil, d.collision(ctx, conn, userID, "email or username in use")
	} else if err != nil {
		return nil, err
	}
	return u, nil
}

// profileUser is a new local user for profile p, with no password hash.
func (d *Database) profileUser(conn *store.Connection, p *customdb.Profile) *store.User {
	now := d.now().UTC()
	name, nickname := defaultNames(p.Name, p.Nickname, p.Email, p.Username)
	return &store.User{
		TenantID: conn.TenantID, UserID: store.StrategyDatabase + "|" + p.UserID,
		Email: p.Email, EmailVerified: p.EmailVerified, Username: p.Username,
		Name: name, Nickname: nickname, GivenName: p.GivenName, FamilyName: p.FamilyName, Picture: p.Picture,
		UserMetadata: p.UserMetadata, AppMetadata: p.AppMetadata,
		Identities: []store.Identity{{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: p.UserID}},
		CreatedAt:  now, UpdatedAt: now,
	}
}

// onConnection reports whether u has the identity of legacy user_id
// profileID on conn.
func onConnection(u *store.User, conn *store.Connection, profileID string) bool {
	for _, id := range u.Identities {
		if id.Connection == conn.Name && id.Provider == store.StrategyDatabase && id.UserID == profileID {
			return true
		}
	}
	return false
}
