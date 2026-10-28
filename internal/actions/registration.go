package actions

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// PreUserRegistration runs the blocking signup flow without writing the prospective user.
// The identity caller applies validated effects in its eventual insert.
func (e *Engine) PreUserRegistration(ctx context.Context, in RegistrationInput) (*Result, error) {
	tenantID := in.Tenant.Tenant.ID
	bound, err := e.Store.Actions().Bindings(ctx, tenantID, TriggerPreUserRegistration)
	if err != nil {
		return nil, e.unrecorded(tenantID, TriggerPreUserRegistration, err)
	}
	if len(bound) == 0 {
		return &Result{}, nil
	}
	f := &flow{tenantID: tenantID, trigger: TriggerPreUserRegistration, handler: handlerFor(TriggerPreUserRegistration), hostname: in.Tenant.Host, units: pinned(bound), acc: newAccum(TriggerPreUserRegistration, nil, nil, false), cache: e.caches.get(tenantID, TriggerPreUserRegistration)}
	f.event = func() map[string]any { return registrationEvent(&in, f.acc) }
	f.validate = func(eff *Effects) error {
		prospective := &store.User{}
		if in.User != nil {
			*prospective = *in.User
		}
		userrules.ApplyPatch(prospective, metadataPatch(eff))
		if err := userrules.CheckMetadata("user_metadata", prospective.UserMetadata); err != nil {
			return err
		}
		return userrules.CheckMetadata("app_metadata", prospective.AppMetadata)
	}
	return e.run(ctx, f, nil)
}

// EnqueuePostUserRegistration snapshots the canonical event through the caller's insert transaction.
func (e *Engine) EnqueuePostUserRegistration(ctx context.Context, tx store.Store, in RegistrationInput) error {
	return e.Enqueue(ctx, tx, AsyncJob{TenantID: in.Tenant.Tenant.ID, Trigger: TriggerPostUserRegistration, Input: postRegistrationEvent(&in, newAccum(TriggerPostUserRegistration, nil, nil, false))})
}
