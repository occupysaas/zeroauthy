package passwordless

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// LinkGrant is a consumed magic link: the signed-in user and the sealed
// authorization parameters the link continues.
type LinkGrant struct {
	User       *store.User
	Connection *store.Connection
	ClientID   string
	AuthParams url.Values
}

func withoutOfflineAccess(scope string) string {
	var out []string
	for _, s := range strings.Fields(scope) {
		if s != "offline_access" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// PeekLink returns an outstanding magic link and its authorization
// parameters without consuming it: link scanners that open it burn nothing.
func (s *Service) PeekLink(ctx context.Context, tid, token string) (*store.PasswordlessCode, url.Values, error) {
	if token == "" {
		return nil, nil, ErrInvalidCode
	}
	hash := secrets.HashToken(token)
	row, err := s.Store.Phone().PeekPasswordlessLink(ctx, tid, hash, s.now())
	if errors.Is(err, store.ErrNotFound) || (err == nil && row.Kind != KindLink) {
		return nil, nil, ErrInvalidCode
	}
	if err != nil {
		return nil, nil, err
	}
	params, err := s.openParams(tid, hash, row.Request)
	if err != nil {
		return nil, nil, err
	}
	return row, params, nil
}

// VerifyLink consumes a magic link once (a conditional delete: concurrent
// uses have one winner) and signs its identifier in.
func (s *Service) VerifyLink(ctx context.Context, tid, token string) (*LinkGrant, error) {
	row, params, err := s.PeekLink(ctx, tid, token)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.Phone().ConsumePasswordlessCode(ctx, tid, row.ConnectionID, row.Identifier, KindLink, row.CodeHash, phonerules.Limits.OTPAttempts, s.now()); err != nil {
		if errors.Is(err, store.ErrPrecondition) {
			return nil, ErrInvalidCode
		}
		return nil, err
	}
	t, err := s.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return nil, err
	}
	conn, err := s.Store.Connections().Get(ctx, tid, row.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	client, err := s.Store.Clients().Get(ctx, tid, row.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	u, err := s.signIn(ctx, t, client, conn, row.Identifier)
	if err != nil {
		return nil, err
	}
	return &LinkGrant{User: u, Connection: conn, ClientID: client.ClientID, AuthParams: params}, nil
}
