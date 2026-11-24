package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/adhub"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ADConnections is the AD/LDAP Connector service (internal/adhub, Plan 38a)
// as the Management API uses it.
type ADConnections interface {
	// Provision creates the connection's ticket and signing key in tx.
	Provision(ctx context.Context, tx store.Store, conn *store.Connection) error
	// TicketURL is the connection's provisioning_ticket_url on host.
	TicketURL(ctx context.Context, host string, conn *store.Connection) (string, error)
	// Online reports whether a connector serves the connection on any
	// replica.
	Online(ctx context.Context, conn *store.Connection) (bool, error)
	// ChangePassword sets a directory password through a connector.
	ChangePassword(ctx context.Context, conn *store.Connection, username, password string) error
}

// prepareAD keeps the connector-managed options of an ad connection
// (LR38a-6): values a Management write sends are dropped and the stored ones
// (prev, nil on create) kept, so exports round-trip without letting an API
// caller replace the connector's certificates.
func prepareAD(spec *connrules.Spec, prev map[string]any) {
	if spec.Strategy != rules.AD || spec.Options.Extra == nil {
		return
	}
	for _, k := range rules.ADManaged {
		delete(spec.Options.Extra, k)
		if v, ok := prev[k]; ok {
			spec.Options.Extra[k] = v
		}
	}
}

var (
	errADPasswordAlone     = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The password of an AD/LDAP user can only be updated on its own"}
	errADNoUsername        = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The user has not signed in through the AD/LDAP connection yet"}
	errADPasswordRejected  = &Error{Status: http.StatusBadRequest, Message: "PasswordStrengthError: The directory refused the password"}
	errADConnectionOffline = &Error{Status: http.StatusServiceUnavailable, Code: "connection_unavailable", Message: "No AD/LDAP Connector answered for this connection"}
	errADUnavailable       = &Error{Status: http.StatusNotImplemented, Code: "ad_unavailable", Message: "AD/LDAP connections are not available with this storage plugin"}
	errNotConnected        = &Error{Status: http.StatusNotFound, Code: "inexistent_connection", Message: "not connected to any node"}
)

// updateADPassword changes an ad user's directory password through a
// connector (Plan 38a): the request must carry only password (and
// connection), and the connector must run with ENABLE_WRITE_BACK. Nothing
// is stored in zeroauthy.
func (h *Handlers) updateADPassword(w http.ResponseWriter, r *http.Request, u *store.User, conn *store.Connection, body map[string]json.RawMessage, password string, changed *bool) {
	for k := range body {
		if k != "password" && k != "connection" {
			Fail(w, errADPasswordAlone)
			return
		}
	}
	if h.AD == nil {
		Fail(w, errADUnavailable)
		return
	}
	username := ""
	for _, id := range u.Identities {
		if id.Connection == conn.Name && id.Provider == store.StrategyAD {
			username, _ = id.ProviderData[federation.ADUsernameKey].(string)
		}
	}
	if username == "" {
		Fail(w, errADNoUsername)
		return
	}
	err := h.AD.ChangePassword(r.Context(), conn, username, password)
	switch {
	case errors.Is(err, adhub.ErrPasswordRejected):
		Fail(w, errADPasswordRejected)
		return
	case errors.Is(err, adhub.ErrUnavailable):
		Fail(w, errADConnectionOffline)
		return
	case err != nil:
		Fail(w, internalError(h, r, "change ad password", err))
		return
	}
	*changed = true
	view, err := h.userView(r, u)
	if err != nil {
		Fail(w, err)
		return
	}
	logDetails(r, "update user", "user_id", u.UserID)
	writeJSON(w, http.StatusOK, view)
}

// adUserConnection is the ad connection of u's primary identity (named
// name when given), or nil.
func (h *Handlers) adUserConnection(r *http.Request, u *store.User, name string) *store.Connection {
	for _, id := range u.Identities {
		if id.Linked() || id.Provider != store.StrategyAD || (name != "" && id.Connection != name) {
			continue
		}
		conn, err := h.Store.Connections().GetByName(r.Context(), u.TenantID, id.Connection)
		if err == nil && conn.Strategy == store.StrategyAD {
			return conn
		}
	}
	return nil
}
