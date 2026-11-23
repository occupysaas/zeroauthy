package mgmt

import (
	"context"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
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
	errADUnavailable = &Error{Status: http.StatusNotImplemented, Code: "ad_unavailable", Message: "AD/LDAP connections are not available with this storage plugin"}
	errNotConnected  = &Error{Status: http.StatusNotFound, Code: "inexistent_connection", Message: "not connected to any node"}
)
