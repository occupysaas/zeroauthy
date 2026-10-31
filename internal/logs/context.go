package logs

import (
	"context"
	"slices"
	"sync"
)

type eventContextKey struct{}
type executionTraceKey struct{}
type executionTrace struct {
	mu  sync.Mutex
	ids []string
}

// WithEvent retains trusted attribution already resolved by the request. It
// never performs enrichment reads, and event-specific fields take precedence.
func WithEvent(ctx context.Context, event Event) context.Context {
	event = Enrich(ctx, event)
	return context.WithValue(ctx, eventContextKey{}, event)
}

// Enrich fills missing attribution from the current flow and carries IDs of
// synchronous Actions that have already run. Final sink scrubbing still applies.
func Enrich(ctx context.Context, event Event) Event {
	base, _ := ctx.Value(eventContextKey{}).(Event)
	pairs := [][2]*string{{&event.TenantID, &base.TenantID},
		{&event.ClientID, &base.ClientID},
		{&event.ClientName, &base.ClientName},
		{&event.Connection, &base.Connection},
		{&event.ConnectionID, &base.ConnectionID},
		{&event.Strategy, &base.Strategy},
		{&event.StrategyType, &base.StrategyType},
		{&event.UserID, &base.UserID},
		{&event.UserName, &base.UserName},
		{&event.OrganizationID, &base.OrganizationID},
		{&event.OrganizationName, &base.OrganizationName},
		{&event.Audience, &base.Audience},
		{&event.Scope, &base.Scope},
		{&event.IP, &base.IP},
		{&event.Hostname, &base.Hostname},
		{&event.UserAgent, &base.UserAgent}}
	for _, pair := range pairs {
		if *pair[0] == "" {
			*pair[0] = *pair[1]
		}
	}
	if trace, ok := ctx.Value(executionTraceKey{}).(*executionTrace); ok {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		for _, id := range trace.ids {
			if !slices.Contains(event.ExecutionIDs, id) {
				event.ExecutionIDs = append(slices.Clone(event.ExecutionIDs), id)
			}
		}
	}
	return event
}

// AddExecution retains a generated execution ID for later flow outcome events.
// The trace is bounded and request-scoped; it never retains Action input/output.
func AddExecution(ctx context.Context, id string) {
	if id == "" {
		return
	}
	if trace, ok := ctx.Value(executionTraceKey{}).(*executionTrace); ok {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		if len(trace.ids) < 128 && !slices.Contains(trace.ids, id) {
			trace.ids = append(trace.ids, id)
		}
	}
}
