package customdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Client makes typed calls to a connection's custom database scripts. It
// is the only reader of a connection's sealed configuration.
type Client struct {
	Exec    Executor
	Wrapper keys.Wrapper
}

// CreateUser is the user object passed to the create script, with Auth0's
// field names.
type CreateUser struct {
	Tenant, ClientID, Connection, Email, Password, Username string
	UserMetadata, AppMetadata                               map[string]any
}

func (u CreateUser) arg() map[string]any {
	m := map[string]any{
		"tenant": u.Tenant, "client_id": u.ClientID, "connection": u.Connection,
		"email": u.Email, "password": u.Password,
	}
	if u.Username != "" {
		m["username"] = u.Username
	}
	if u.UserMetadata != nil {
		m["user_metadata"] = u.UserMetadata
	}
	if u.AppMetadata != nil {
		m["app_metadata"] = u.AppMetadata
	}
	return m
}

// run executes one script of conn. A script the connection does not define
// is ErrNoScript, without calling Exec.
func (c *Client) run(ctx context.Context, conn *store.Connection, script string, args ...any) (json.RawMessage, error) {
	req, err := c.request(conn, script, args)
	if err != nil {
		return nil, err
	}
	raw, err := c.Exec.Execute(ctx, req)
	// The caller logs a script's error message, so mask it here too.
	return raw, NewRedactor(req.Config).RedactError(err)
}

// request builds the execution of script of conn with args: the script's
// source and the connection's opened configuration.
func (c *Client) request(conn *store.Connection, script string, args []any) (Request, error) {
	src := conn.CustomScripts[script]
	if src == "" {
		return Request{}, ErrNoScript
	}
	cfg, err := keys.OpenConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, conn.ConfigurationSealed)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return Request{
		TenantID: conn.TenantID, ConnectionID: conn.ID, Script: script, Source: src, Config: cfg, Args: args,
	}, nil
}

// Try runs script of conn with args exactly as a login or sign-up would,
// whether or not the connection has custom database scripts switched on,
// and returns the callback value or the script's error. onLogs, when set,
// receives the script's console output. Configuration values are masked
// (see Redactor) in the console output, the result and a script error.
// Nothing is stored.
func (c *Client) Try(ctx context.Context, conn *store.Connection, script string, args []any, onLogs func([]string)) (json.RawMessage, error) {
	req, err := c.request(conn, script, args)
	if err != nil {
		return nil, err
	}
	red := NewRedactor(req.Config)
	if onLogs != nil {
		req.OnLogs = func(l []string) { onLogs(red.RedactAll(l)) }
	}
	raw, err := c.Exec.Execute(ctx, req)
	if err != nil {
		return nil, red.RedactError(err)
	}
	return red.RedactJSON(raw), nil
}

// ScriptArgCounts is the number of arguments the runner passes to each
// script before its callback (Auth0's signatures): login(email, password),
// getUser(email), create(user), verify(email), changePassword(email,
// newPassword), delete(id) and changeEmail(email, newEmail, verified).
var ScriptArgCounts = map[string]int{
	store.ScriptLogin: 2, store.ScriptGetUser: 1, store.ScriptCreate: 1, store.ScriptVerify: 1,
	store.ScriptChangePassword: 2, store.ScriptDelete: 1, store.ScriptChangeEmail: 3,
}

// Login runs the login script. It returns the profile, or a *ScriptError,
// ErrTimeout, ErrUnavailable, ErrNoScript or ErrBadProfile.
func (c *Client) Login(ctx context.Context, conn *store.Connection, identifier, password string) (*Profile, error) {
	raw, err := c.run(ctx, conn, store.ScriptLogin, identifier, password)
	if err != nil {
		return nil, err
	}
	return decodeProfile(raw)
}

// GetUser runs the get_user script. It returns nil, nil when the script
// reports no user.
func (c *Client) GetUser(ctx context.Context, conn *store.Connection, identifier string) (*Profile, error) {
	raw, err := c.run(ctx, conn, store.ScriptGetUser, identifier)
	if err != nil {
		return nil, err
	}
	if isNull(raw) {
		return nil, nil
	}
	return decodeProfile(raw)
}

// Create runs the create script.
func (c *Client) Create(ctx context.Context, conn *store.Connection, u CreateUser) error {
	_, err := c.run(ctx, conn, store.ScriptCreate, u.arg())
	return err
}

// errBadResult is a change_password result that is neither a boolean nor an
// object.
var errBadResult = errors.New("customdb: change_password returned an unexpected result")

// ChangePassword runs the change_password script. It returns false when the
// script reports the password was not changed. An object result (Auth0
// scripts may pass one with last_password_reset) counts as changed.
func (c *Client) ChangePassword(ctx context.Context, conn *store.Connection, identifier, newPassword string) (bool, error) {
	raw, err := c.run(ctx, conn, store.ScriptChangePassword, identifier, newPassword)
	if err != nil {
		return false, err
	}
	raw = bytes.TrimSpace(raw)
	switch {
	case isNull(raw), bytes.Equal(raw, []byte("false")):
		return false, nil
	case bytes.Equal(raw, []byte("true")), len(raw) > 0 && raw[0] == '{':
		return true, nil
	}
	return false, errBadResult
}

func isNull(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || bytes.Equal(raw, []byte("null"))
}
