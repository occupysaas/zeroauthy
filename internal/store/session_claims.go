package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// SessionClaimsSetter updates one client's claims without replacing the others.
type SessionClaimsSetter interface {
	SetClaims(context.Context, string, string, string, string) (*LoginSession, error)
}

func ValidateSessionClaims(raw string) error {
	if len(raw) > 100000 {
		return fmt.Errorf("store: session claims exceed 100000 bytes")
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil || claims == nil {
		return fmt.Errorf("store: session claims must be an object")
	}
	return nil
}
func SetSessionClaims(ctx context.Context, st Store, tid, id, client, raw string) (*LoginSession, error) {
	if client == "" {
		return nil, ErrInvalid
	}
	if err := ValidateSessionClaims(raw); err != nil {
		return nil, err
	}
	repo, ok := st.Sessions().(SessionClaimsSetter)
	if !ok {
		// Empty effects must not require a new RPC from an old plugin. An old
		// driver cannot have written custom claims; still check the session and
		// fail closed if it does expose existing claims that need clearing.
		var claims map[string]any
		_ = json.Unmarshal([]byte(raw), &claims)
		if len(claims) == 0 {
			current, err := st.Sessions().Get(ctx, tid, id)
			if err != nil {
				return nil, err
			}
			if current.UserinfoClaims[client] == "" {
				return current, nil
			}
		}
		return nil, ErrSessionLimitsUnavailable
	}
	return repo.SetClaims(ctx, tid, id, client, raw)
}
