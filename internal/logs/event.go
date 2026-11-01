// Package logs records scrubbed tenant events without waiting on storage.
package logs

import (
	"context"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Event struct {
	TenantID, Type, Description                              string
	ClientID, ClientName, Connection, ConnectionID, Strategy string
	StrategyType, UserID, UserName, Audience, Scope          string
	OrganizationID, OrganizationName, Hostname               string
	IP, UserAgent                                            string
	Date                                                     time.Time
	Details                                                  map[string]any
	ExecutionIDs                                             []string
}
type Recorder interface{ Record(context.Context, Event) }
type nop struct{}

func (nop) Record(context.Context, Event) {}

var Nop Recorder = nop{}

// FromRequest uses the client address established by the authenticated proxy
// boundary, when present. It never trusts forwarded headers on its own.
func FromRequest(r *http.Request) Event {
	e := Event{IP: httpx.RecordedIP(r, false), UserAgent: r.UserAgent(), Hostname: r.Host}
	if res, ok := tenant.FromContext(r.Context()); ok {
		if res.Host != "" {
			e.Hostname = res.Host
		}
		if res.Tenant != nil {
			e.TenantID = res.Tenant.ID
		}
	}
	return e
}
