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
	src := conn.CustomScripts[script]
	if src == "" {
		return nil, ErrNoScript
	}
	cfg, err := keys.OpenConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, conn.ConfigurationSealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return c.Exec.Execute(ctx, Request{
		TenantID: conn.TenantID, ConnectionID: conn.ID, Script: script, Source: src, Config: cfg, Args: args,
	})
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
