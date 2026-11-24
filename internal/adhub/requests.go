package adhub

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Outcomes of a connector request (LR38a-9). Anything else, a timeout or no
// connector online is ErrUnavailable.
var (
	ErrWrongCredentials       = errors.New("adhub: wrong username or password")
	ErrAccountBlocked         = errors.New("adhub: account disabled, expired or locked")
	ErrPasswordChangeRequired = errors.New("adhub: password expired or change required")
	ErrPasswordRejected       = errors.New("adhub: the directory refused the new password")
)

// classify maps a connector error class to an outcome.
func classify(e *ConnectorError) error {
	switch e.Name {
	case "WrongUsername", "WrongPassword":
		return ErrWrongCredentials
	case "AccountDisabled", "AccountExpired", "AccountLocked":
		return ErrAccountBlocked
	case "PasswordExpired", "PasswordChangeRequired":
		return ErrPasswordChangeRequired
	case "PasswordComplexityError", "InsufficientAccessRightsError":
		return ErrPasswordRejected
	}
	return ErrUnavailable
}

func unavailable(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	return errors.Join(ErrUnavailable, err)
}

func (s *Service) hub() (*Hub, error) {
	if s.Hub == nil {
		return nil, ErrUnavailable
	}
	return s.Hub, nil
}

// Authenticate checks username and password through a connector of conn and
// returns the connector's profile.
func (s *Service) Authenticate(ctx context.Context, conn *store.Connection, username, password string) (json.RawMessage, error) {
	h, err := s.hub()
	if err != nil {
		return nil, err
	}
	reply, err := h.Call(ctx, conn.TenantID, conn.ID, OpAuthenticateUser, map[string]any{"username": username, "password": password, "escaped": false})
	if err != nil {
		return nil, unavailable(err)
	}
	if reply.Err != nil {
		return nil, classify(reply.Err)
	}
	if len(reply.Profile) == 0 || string(reply.Profile) == "null" {
		return nil, ErrUnavailable
	}
	return reply.Profile, nil
}

// ChangePassword sets a user's directory password through a connector of
// conn (the connector serves it only with ENABLE_WRITE_BACK; otherwise it
// never answers and the request times out).
func (s *Service) ChangePassword(ctx context.Context, conn *store.Connection, username, password string) error {
	h, err := s.hub()
	if err != nil {
		return err
	}
	reply, err := h.Call(ctx, conn.TenantID, conn.ID, OpChangePassword, map[string]any{"username": username, "password": password, "escaped": false})
	if err != nil {
		return unavailable(err)
	}
	if reply.Err != nil {
		return classify(reply.Err)
	}
	return nil
}

// ListGroups returns the directory's groups as the connector reports them
// (names, or objects with GROUP_PROPERTIES).
func (s *Service) ListGroups(ctx context.Context, conn *store.Connection, limit int) (json.RawMessage, error) {
	h, err := s.hub()
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if limit > 0 {
		claims["limit"] = limit
	}
	reply, err := h.Call(ctx, conn.TenantID, conn.ID, OpListGroups, claims)
	if err != nil {
		return nil, unavailable(err)
	}
	if reply.Err != nil {
		return nil, classify(reply.Err)
	}
	return reply.Groups, nil
}
