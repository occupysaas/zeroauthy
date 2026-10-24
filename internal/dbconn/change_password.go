package dbconn

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// ChangePassword implements POST /dbconnections/change_password (D-0019).
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	body, ok := parseBody(w, r)
	if !ok {
		return
	}
	fields := map[string]string{}
	for _, k := range []string{"client_id", "connection", "email"} {
		if v, present := body[k]; present && v != nil {
			s, isStr := v.(string)
			if !isStr {
				writeErr(w, http.StatusBadRequest, "invalid_request", k+" must be a string")
				return
			}
			fields[k] = s
		}
	}
	for _, k := range []string{"connection", "email"} {
		if fields[k] == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", k+" is required")
			return
		}
	}
	tenantID := res.Tenant.ID
	if id := fields["client_id"]; id != "" {
		if _, err := h.Store.Clients().Get(ctx, tenantID, id); errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusBadRequest, "invalid_request", "unknown client")
			return
		} else if err != nil {
			h.internal(w, r, "load client", err)
			return
		}
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, fields["connection"])
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.Strategy != store.StrategyDatabase) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "unknown connection")
		return
	} else if err != nil {
		h.internal(w, r, "load connection", err)
		return
	}
	if id := fields["client_id"]; id != "" && !slices.Contains(conn.EnabledClients, id) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "the connection is not enabled for this application")
		return
	}
	// An unknown user gets the same answer and no email, so the response
	// does not reveal which addresses have accounts (D-0018).
	// A custom database script that fails or refuses gets the same answer
	// too; identity has logged it (D-0023).
	user, err := h.FindByEmail(ctx, conn, fields["email"])
	var ue *identity.UnauthorizedError
	switch {
	case err == nil:
		if err := h.RequestReset(res, conn, user, fields["client_id"], i18n.Negotiate(res.Tenant, "", r.Header.Get("Accept-Language"))); err != nil {
			h.internal(w, r, "reset admission", err)
			return
		}
	case errors.Is(err, store.ErrNotFound), errors.As(err, &ue), errors.Is(err, identity.ErrScript):
	default:
		h.internal(w, r, "find user", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("A password reset link has been sent to the email address."))
}

// FindByEmail returns the user of conn whose email address is email, or
// store.ErrNotFound. A username never matches. On a legacy custom database
// the get_user script decides (identity.Database.FindForReset).
func (h *Handlers) FindByEmail(ctx context.Context, conn *store.Connection, email string) (*store.User, error) {
	return h.Database.FindForReset(ctx, conn, email)
}
