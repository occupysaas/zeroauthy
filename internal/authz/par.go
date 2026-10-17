package authz

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Pushed authorization requests (RFC 9126, D-0028, D-0029).
const (
	RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	// PARLifetime is fixed, as on Auth0.
	PARLifetime = 30 * time.Second
	// MaxExtParams is how many ext-* parameters a pushed request may carry.
	MaxExtParams = 10
	ExtPrefix    = "ext-"
)

// pushedKey marks a request that came from /oauth/par in stored Params. Like
// ParamStage it is not a request parameter: ParseRequest never reads it.
const pushedKey = "za_pushed"

func errPushedUnusable() *Error {
	return errInvalidRequest("request_uri is invalid, expired or already used")
}

// resolvePushed replaces a request_uri request with the request it names.
// It returns nil, nil for strict third-party clients: ValidateRequest refuses
// their request_uri (D-0025). Every error is shown on the error page; the
// pushed redirect_uri is unknown until the request is found.
func (h *Handlers) resolvePushed(ctx context.Context, t *store.Tenant, q url.Values) (*Request, *Error) {
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, errInvalidRequest("client_id is required")
	}
	client, err := h.Store.Clients().Get(ctx, t.ID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidRequest("unknown client")
	}
	if err != nil {
		return nil, errServer()
	}
	if access.Strict(client) {
		return nil, nil
	}
	if !t.PushedAuthorizationRequestsSupported {
		return nil, errInvalidRequest("pushed authorization requests are not enabled") // P6b
	}
	id, ok := strings.CutPrefix(q.Get("request_uri"), RequestURIPrefix)
	if !ok || id == "" {
		return nil, errPushedUnusable()
	}
	now := h.now()
	p, err := h.Store.PushedAuthRequests().Consume(ctx, t.ID, secrets.HashToken(id), now)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrAlreadyUsed):
		return nil, errPushedUnusable() // P4a
	case err != nil:
		h.log().ErrorContext(ctx, "consume pushed request", "tenant", t.ID, "err", err)
		return nil, errServer()
	}
	if p.ClientID != client.ClientID || !now.Before(p.ExpiresAt) {
		return nil, errPushedUnusable() // P4b, P4c
	}
	// P1: query parameters other than client_id and request_uri are ignored.
	req := RequestFromParams(p.Params)
	req.ClientID = p.ClientID // the stored binding wins over Params
	req.Pushed = true
	return &req, nil
}
