package mgmt

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TryConnectionPasswordless uses the operator's tenant grant as authority to
// run a real start with the saved connection and its configured delivery.
func (h *Handlers) TryConnectionPasswordless(w http.ResponseWriter, r *http.Request, tenantName, id string) {
	base, ok := tenant.FromContext(r.Context())
	if !ok || h.SystemHost == "" || base.Host != tenant.NormalizeHost(h.SystemHost) {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return
	}
	caller, ok := CallerFrom(r.Context())
	if !ok || caller.Kind != Operator || !manages(caller.Tenants, tenantName) {
		WriteError(w, http.StatusForbidden, "insufficient_scope", "The operator does not manage this tenant")
		return
	}
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	ctx := r.Context()
	t, err := h.Store.Tenants().GetByName(ctx, tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "try passwordless", err))
		return
	}
	if t.Reserved {
		WriteError(w, http.StatusForbidden, "operation_not_supported", "Passwordless test sends require a non-reserved tenant")
		return
	}
	conn, err := h.Store.Connections().Get(ctx, t.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "try passwordless", err))
		return
	}
	if !connrules.IsPasswordless(conn.Strategy) || conn.Name != conn.Strategy {
		Fail(w, badBody("the connection must be an email or SMS passwordless connection"))
		return
	}
	if h.Passwordless == nil {
		WriteError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Passwordless delivery is unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in := passwordless.StartInput{
		TenantID: t.ID, Connection: conn.Name, ConnectionID: conn.ID,
		IP: httpx.ClientIP(r, h.TrustProxyHeaders), UserAgent: r.UserAgent(),
		Locale: r.Header.Get("x-request-language"),
		Origin: strings.TrimSuffix(tenant.ManagementAPIIdentifier(t, h.BaseDomain), "/api/v2/"),
	}
	fields := map[string]*string{"client_id": &in.ClientID, "send": &in.Send}
	if conn.Strategy == connrules.StrategyEmail {
		fields["email"] = &in.Email
	} else {
		fields["phone_number"] = &in.PhoneNumber
	}
	for key, raw := range body {
		field, ok := fields[key]
		if !ok {
			Fail(w, badBody("unknown property for this passwordless connection"))
			return
		}
		if err := decodeString(raw, field); err != nil {
			Fail(w, badBody("%s must be a string", key))
			return
		}
	}
	if strings.TrimSpace(in.ClientID) == "" {
		Fail(w, badBody("client_id is required"))
		return
	}
	if _, provided := body["send"]; provided && in.Send != passwordless.KindCode && in.Send != passwordless.KindLink {
		Fail(w, badBody("send must be code or link"))
		return
	}
	if conn.Strategy == connrules.StrategyEmail && in.Send != passwordless.KindCode && in.Origin == "" {
		Fail(w, badBody("a public tenant host is required for magic links"))
		return
	}

	ctx = logscrub.WithCredentials(r.Context(), in.Email, in.PhoneNumber)
	logDetails(r, "try passwordless", "target_tenant", t.Name, "connection_id", id)
	_, err = h.Passwordless.Start(ctx, in)
	var refused *passwordless.Error
	switch {
	case errors.As(err, &refused):
		if refused.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(refused.RetryAfter))
		}
		WriteError(w, refused.Status, refused.Code, refused.Description)
	case errors.Is(err, store.ErrPhoneUnavailable):
		WriteError(w, http.StatusNotImplemented, "phone_unavailable", "Passwordless authentication is not available with this storage plugin")
	case err != nil:
		Fail(w, internalError(h, r.WithContext(ctx), "try passwordless", err))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
