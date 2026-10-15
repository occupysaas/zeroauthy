package dbconn

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
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
	if !h.IPThrottle.Attempt(identity.IPThrottleKey(tenantID, httpx.ClientIP(r, h.TrustProxyHeaders))) {
		writeErr(w, http.StatusTooManyRequests, "too_many_requests", "too many requests from this address; try again later")
		return
	}
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
	user, err := h.Store.Users().FindByLogin(ctx, tenantID, conn.Name, identity.NormalizeLogin(fields["email"]))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "user_not_found", "the user does not exist")
		return
	} else if err != nil {
		h.internal(w, r, "find user", err)
		return
	}
	h.RequestReset(res, conn, user, fields["client_id"], i18n.Negotiate(res.Tenant, "", r.Header.Get("Accept-Language")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("A password reset link has been sent to the email address."))
}
