package actions

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrEmailUnbound prevents silently accepting mail without a delivery Action.
var ErrEmailUnbound = errors.New("actions: no custom email provider Action is bound")

type EmailOutcome struct {
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
}

// EnqueueEmail snapshots the rendered hand-off in the caller's transaction.
func (e *Engine) EnqueueEmail(ctx context.Context, tx store.Store, in EmailInput) error {
	bound, err := tx.Actions().Bindings(ctx, in.Tenant, TriggerCustomEmailProvider)
	if err != nil {
		return err
	}
	if len(bound) == 0 {
		return ErrEmailUnbound
	}
	if in.TenantInfo == nil {
		in.TenantInfo, err = tx.Tenants().Get(ctx, in.Tenant)
		if err != nil {
			return err
		}
	}
	return e.Enqueue(ctx, tx, AsyncJob{TenantID: in.Tenant, Trigger: TriggerCustomEmailProvider, Input: emailEvent(&in, newAccum(TriggerCustomEmailProvider, nil, nil, false))})
}

// RunEmailNow executes exactly one attempt for the console, without enqueuing retries.
func (e *Engine) RunEmailNow(ctx context.Context, in EmailInput) (EmailOutcome, error) {
	out := EmailOutcome{Status: "failed"}
	bound, err := e.Store.Actions().Bindings(ctx, in.Tenant, TriggerCustomEmailProvider)
	if err != nil {
		return out, err
	}
	if len(bound) == 0 {
		return out, ErrEmailUnbound
	}
	if in.TenantInfo == nil {
		in.TenantInfo, err = e.Store.Tenants().Get(ctx, in.Tenant)
		if err != nil {
			return out, err
		}
	}
	f := &flow{tenantID: in.Tenant, trigger: TriggerCustomEmailProvider, handler: handlerFor(TriggerCustomEmailProvider), units: pinned(bound), acc: newAccum(TriggerCustomEmailProvider, nil, nil, false), cache: e.caches.get(in.Tenant, TriggerCustomEmailProvider)}
	f.event = func() map[string]any { return emailEvent(&in, f.acc) }
	result, err := e.run(ctx, f, nil)
	if err != nil {
		var flowErr *ErrFlow
		if errors.As(err, &flowErr) {
			out.ExecutionID = flowErr.ExecutionID
		}
		// As for a job, a recorded drop is the outcome even if a later Action failed.
		if f.dropped != nil && out.ExecutionID != "" {
			out.Status, out.Reason = f.dropped.Kind, f.dropped.Reason
			return out, nil
		}
		return out, err
	}
	out.Status = "sent"
	out.ExecutionID = result.ExecutionID
	if n := result.Notification; f.dropped != nil {
		out.Status, out.Reason = f.dropped.Kind, f.dropped.Reason
	} else if n != nil {
		out.Status, out.Reason = n.Kind, n.Reason
	}
	return out, nil
}
