package oauth

import (
	"context"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (h *Handlers) event(ctx context.Context, res tenant.Resolved, c *store.Client, code string, conn *store.Connection, userID string) {
	ri := requestInfoFrom(ctx)
	e := logs.Event{TenantID: res.Tenant.ID, Type: code, Hostname: res.Host, IP: ri.IP, UserAgent: ri.UserAgent, UserID: userID}
	if c != nil {
		e.ClientID = c.ClientID
		e.ClientName = c.Name
	}
	if conn != nil {
		e.Connection = conn.Name
		e.ConnectionID = conn.ID
		e.Strategy = conn.Strategy
		e.StrategyType = logs.StrategyType(conn.Strategy)
	}
	logs.RecordEvent(ctx, h.Recorder, e)
}

func requestEventContext(r *http.Request) context.Context {
	return withRequestInfo(r.Context(), r, httpx.RecordedIP(r, false), nil)
}

func eventConnection(user *store.User, connectionID string) *store.Connection {
	conn := &store.Connection{ID: connectionID}
	if user != nil && len(user.Identities) == 1 {
		conn.Name = user.Identities[0].Connection
		conn.Strategy = user.Identities[0].Provider
	}
	return conn
}
