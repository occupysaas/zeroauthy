package mgmt

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// domainEvent uses resources the operation already resolved. Actor identity
// remains in the single Management operation event; UserID here is its subject.
func (h *Handlers) domainEvent(r *http.Request, typ string, user *store.User, conn *store.Connection, details map[string]any) {
	event := logs.FromRequest(r)
	event.Type = typ
	event.Details = details
	if caller, ok := CallerFrom(r.Context()); ok {
		event.ClientID = caller.ClientID
	}
	if user != nil {
		event.UserID = user.UserID
		event.UserName = user.Email
		if conn == nil && len(user.Identities) == 1 {
			event.Connection = user.Identities[0].Connection
			event.Strategy = user.Identities[0].Provider
			event.StrategyType = logs.StrategyType(event.Strategy)
		}
	}
	if conn != nil {
		event.ConnectionID = conn.ID
		event.Connection = conn.Name
		event.Strategy = conn.Strategy
		event.StrategyType = logs.StrategyType(conn.Strategy)
	}
	logs.RecordEvent(r.Context(), h.Recorder, event)
}
