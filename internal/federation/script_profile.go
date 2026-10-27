package federation

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/federation/script"
)

// ErrScriptUnavailable reports that custom OAuth2 login cannot run because
// the restricted profile script runtime is missing or failed its capability
// probe. Google, OIDC and database login are unaffected.
var ErrScriptUnavailable = errors.New("federation: custom OAuth2 login unavailable: no restricted profile script runtime")

// WithScripts sets the executor OAuth2 connections run their
// fetchUserProfile scripts with, and returns ps.
func (ps *Providers) WithScripts(e script.Executor) *Providers {
	ps.scripts = e
	return ps
}

// scriptContext is the documented script context: the successful token
// response's allowlisted scalars, absent keys omitted. id_token is passed
// opaque, never treated as verified identity.
func scriptContext(t TokenSet) map[string]any {
	c := map[string]any{"access_token": t.AccessToken, "token_type": t.TokenType}
	for k, v := range map[string]string{"refresh_token": t.RefreshToken, "scope": t.Scope, "id_token": t.IDToken} {
		if v != "" {
			c[k] = v
		}
	}
	if t.ExpiresIn > 0 {
		c["expires_in"] = t.ExpiresIn
	}
	return c
}

// scriptProfile runs the connection's script and normalizes its profile. The
// script cannot set app_metadata, identities or any local attribute.
func (ps *Providers) scriptProfile(ctx context.Context, in ExchangeInput, tokens TokenSet) (Profile, error) {
	if ps.scripts == nil {
		return Profile{}, ErrScriptUnavailable
	}
	raw, err := ps.scripts.Execute(ctx, script.Request{
		TenantID: in.Cache.TenantID, ConnectionID: in.Cache.ConnectionID, Source: in.Config.Script,
		AccessToken: tokens.AccessToken, Context: scriptContext(tokens),
	})
	switch {
	case errors.Is(err, script.ErrUnavailable):
		return Profile{}, fmt.Errorf("%w: %w", ErrScriptUnavailable, err)
	case err != nil:
		return Profile{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	return NormalizeProfile(raw)
}
