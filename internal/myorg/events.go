package myorg

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/logs"
)

// event records a my_organization_api_* log event (the guide's types).
func (h *Handlers) event(r *http.Request, c *Caller, typ string) {
	ctx := r.Context()
	logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: c.TenantID, UserID: c.UserID, ClientID: c.ClientID, OrganizationID: c.Org.ID, OrganizationName: c.Org.Name, Type: typ, Date: h.now()})
}
