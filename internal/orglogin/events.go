package orglogin

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type membershipEventsKey struct{}
type membershipEvents struct{ events []logs.Event }

// WithMembershipEvents stages successful insertions until the outer business
// transaction commits. A rollback discards them together with its membership.
func WithMembershipEvents(ctx context.Context, st store.Store, fn func(context.Context, store.Store) error) error {
	if pending, ok := ctx.Value(membershipEventsKey{}).(*membershipEvents); ok {
		start := len(pending.events)
		err := st.WithTx(ctx, func(tx store.Store) error { return fn(ctx, tx) })
		if err != nil {
			pending.events = pending.events[:start]
		}
		return err
	}
	pending := &membershipEvents{}
	ctx = context.WithValue(ctx, membershipEventsKey{}, pending)
	err := st.WithTx(ctx, func(tx store.Store) error { return fn(ctx, tx) })
	if err == nil {
		for _, event := range pending.events {
			logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), event)
		}
	}
	return err
}
