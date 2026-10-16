package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// decide runs the access decision for a token-endpoint flow. rs is nil when
// there is no audience.
func (h *Handlers) decide(ctx context.Context, tenantID string, flow access.Flow, c *store.Client, rs *store.ResourceServer, scopes []string) (access.Decision, *Error) {
	in := access.Input{Flow: flow, Client: c, API: rs, Scopes: scopes}
	if rs != nil {
		g, err := h.Store.ClientGrants().Find(ctx, tenantID, c.ClientID, rs.Identifier, access.SubjectType(flow))
		switch {
		case err == nil:
			in.ClientGrant = g
		case !errors.Is(err, store.ErrNotFound):
			h.log().ErrorContext(ctx, "load client grant", "tenant", tenantID, "client_id", c.ClientID, "err", err)
			return access.Decision{}, serverError()
		}
	}
	d := access.Decide(in)
	if d.Err != nil {
		status := http.StatusForbidden // unauthorized_client, access_denied
		if d.Err.Code == "invalid_request" {
			status = http.StatusBadRequest // a refused user flow (observed, D-0025)
		}
		return d, &Error{Status: status, Code: d.Err.Code, Description: d.Err.Description}
	}
	return d, nil
}
