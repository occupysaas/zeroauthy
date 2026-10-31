package login

import (
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (h *Handlers) event(r *http.Request, f *flow, code string, u *store.User) {
	e := logs.FromRequest(r)
	e.Type = code
	if f != nil {
		e.TenantID = f.res.Tenant.ID
		e.ClientID = f.txn.ClientID
		e.ClientName = f.clientName
		e.OrganizationID = f.txn.Params[store.TxnParamOrgID]
		if f.conn != nil {
			e.Connection = f.conn.Name
			e.ConnectionID = f.conn.ID
			e.Strategy = f.conn.Strategy
			e.StrategyType = logs.StrategyType(f.conn.Strategy)
		}
	}
	if u != nil {
		e.UserID = u.UserID
		e.UserName = u.Name
	}
	logs.RecordEvent(r.Context(), h.Recorder, e)
}
func (h *Handlers) maskRequest(r *http.Request) {
	values := []string{}
	for _, fields := range []url.Values{r.URL.Query(), r.PostForm} {
		for key, entries := range fields {
			if logscrub.SensitiveKey(key) || key == "code" || key == "ticket" {
				values = append(values, entries...)
			}
		}
	}
	ctx := logscrub.WithCredentials(logscrub.WithValues(r.Context(), values...), values...)
	*r = *r.WithContext(logs.WithRecorder(ctx, h.Recorder))
}

// ticketEvent uses only the trusted identity and connection resolved by a ticket.
func (h *Handlers) ticketEvent(r *http.Request, code, clientID string, conn *store.Connection, u *store.User) {
	f := &flow{txn: &store.AuthTransaction{ClientID: clientID}, conn: conn}
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		return
	}
	f.res = res
	h.event(r, f, code, u)
}

func (h *Handlers) withFlowEvent(r *http.Request, f *flow) {
	e := logs.FromRequest(r)
	e.ClientID = f.txn.ClientID
	e.ClientName = f.clientName
	e.OrganizationID = f.txn.Params[store.TxnParamOrgID]
	if f.conn != nil {
		e.Connection = f.conn.Name
		e.ConnectionID = f.conn.ID
		e.Strategy = f.conn.Strategy
		e.StrategyType = logs.StrategyType(f.conn.Strategy)
	}
	*r = *r.WithContext(logs.WithEvent(r.Context(), e))
}
