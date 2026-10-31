package dbconn

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) event(r *http.Request, code, clientID string, conn *store.Connection, user *store.User) {
	e := logs.FromRequest(r)
	e.Type = code
	e.ClientID = clientID
	if conn != nil {
		e.Connection = conn.Name
		e.ConnectionID = conn.ID
		e.Strategy = conn.Strategy
		e.StrategyType = "database"
	}
	if user != nil {
		e.UserID = user.UserID
		e.UserName = user.Name
	}
	logs.RecordEvent(r.Context(), h.Recorder, e)
}
