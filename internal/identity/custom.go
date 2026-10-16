package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// IsCustom reports whether conn runs custom database scripts.
func IsCustom(conn *store.Connection) bool { return conn.EnabledDatabaseCustomization }

// IsLegacy reports whether conn's custom database scripts are the source of
// truth (customized, not import mode).
func IsLegacy(conn *store.Connection) bool { return IsCustom(conn) && !conn.ImportMode }

// errImportMode keeps import mode from silently taking the legacy path
// until it is implemented.
var errImportMode = errors.New("identity: import mode is not yet implemented")

// errNoClient is a customized connection on a server built without a
// script client.
var errNoClient = errors.New("identity: custom database scripts are not configured")

// scriptErr maps a script failure. A script's UnauthorizedError becomes
// *UnauthorizedError; everything else is logged and wrapped in ErrScript.
func (d *Database) scriptErr(ctx context.Context, conn *store.Connection, script string, err error) error {
	kind, msg := "error", err.Error()
	var se *customdb.ScriptError
	switch {
	case errors.As(err, &se):
		kind, msg = se.Kind, se.Message
		if se.Kind == customdb.KindUnauthorized {
			d.log().InfoContext(ctx, "custom database script refused the user",
				"tenant", conn.TenantID, "connection", conn.Name, "script", script, "kind", kind, "message", msg)
			return &UnauthorizedError{Message: se.Message}
		}
	case errors.Is(err, customdb.ErrTimeout):
		kind = "timeout"
	case errors.Is(err, customdb.ErrUnavailable):
		kind = "unavailable"
	case errors.Is(err, customdb.ErrNoScript):
		kind = "no_script"
	case errors.Is(err, customdb.ErrBadProfile):
		kind = "bad_profile"
	}
	d.log().ErrorContext(ctx, "custom database script failed",
		"tenant", conn.TenantID, "connection", conn.Name, "script", script, "kind", kind, "message", msg)
	return fmt.Errorf("%w: %w", ErrScript, err)
}

// scripts returns the client, or an ErrScript when there is none or conn is
// in import mode (Task 5).
func (d *Database) scripts(ctx context.Context, conn *store.Connection, script string) (*customdb.Client, error) {
	if conn.ImportMode {
		// Task 5 replaces this guard with the import-mode flow.
		return nil, d.scriptErr(ctx, conn, script, errImportMode)
	}
	if d.Scripts == nil {
		return nil, d.scriptErr(ctx, conn, script, errNoClient)
	}
	return d.Scripts, nil
}

// customLogin authenticates through the login script. The script decides
// every time; the local record is never used to check a password.
func (d *Database) customLogin(ctx context.Context, conn *store.Connection, login, password string) (*store.User, error) {
	login = strings.TrimSpace(login)
	if len(password) > maxPasswordBytes || len(login) > maxLoginLength {
		return nil, ErrInvalidCredentials
	}
	c, err := d.scripts(ctx, conn, store.ScriptLogin)
	if err != nil {
		return nil, err
	}
	p, err := c.Login(ctx, conn, login, password)
	if err != nil {
		var se *customdb.ScriptError
		if errors.As(err, &se) && se.Kind == customdb.KindWrongCredentials {
			return nil, ErrInvalidCredentials
		}
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
		// Even a refusal is a failure here: the account was just created.
		return nil, fmt.Errorf("%w: confirming login after create: %w", ErrScript, d.scriptErr(ctx, conn, store.ScriptLogin, err))
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
		name, nickname := defaultNames(p.Name, p.Nickname, p.Email, p.Username)
		u = &store.User{
			TenantID: conn.TenantID, UserID: userID,
			Email: p.Email, EmailVerified: p.EmailVerified, Username: p.Username,
			Name: name, Nickname: nickname, GivenName: p.GivenName, FamilyName: p.FamilyName, Picture: p.Picture,
			UserMetadata: p.UserMetadata, AppMetadata: p.AppMetadata,
			Identities: []store.Identity{{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: p.UserID}},
			CreatedAt:  now, UpdatedAt: now,
		}
		if err := d.Store.Users().Create(ctx, u); errors.Is(err, store.ErrConflict) {
			return nil, d.collision(ctx, conn, userID, "email, username or user_id in use")
		} else if err != nil {
			return nil, err
		}
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	onConn := false
	for _, id := range u.Identities {
		if id.Connection == conn.Name && id.Provider == store.StrategyDatabase && id.UserID == p.UserID {
			onConn = true
		}
	}
	if !onConn {
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
