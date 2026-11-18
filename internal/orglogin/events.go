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

// StageMembershipEvents lets proof services own the transaction while callers
// retain the success events until its actual commit result is known.
func StageMembershipEvents(ctx context.Context) (context.Context, func(error)) {
	if _, ok := ctx.Value(membershipEventsKey{}).(*membershipEvents); ok {
		return ctx, func(error) {}
	}
	pending := &membershipEvents{}
	scoped := context.WithValue(ctx, membershipEventsKey{}, pending)
	return scoped, func(err error) {
		if err == nil {
			for _, event := range pending.events {
				logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), event)
			}
		}
	}
}
