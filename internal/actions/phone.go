package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// phoneRetries is the documented retry count of custom-phone-provider.
var phoneRetries = phonerules.ActionTrigger(TriggerCustomPhoneProvider).Retries

// PhoneInput is one phone Action hand-off. Message.Code reaches the event
// only; it is masked in console output, errors, records and logs.
type PhoneInput struct {
	Tenant  string
	Message phone.Message
	// MessageType is the template type (otp_verify, otp_enroll, ...).
	MessageType string
	// AsText and AsVoice are both rendered bodies (custom-phone-provider).
	AsText, AsVoice string
	ConnectionID    string
	Request         RequestInfo
}

// phoneSnapshot is PhoneInput with its profile records loaded.
type phoneSnapshot struct {
	in         *PhoneInput
	tenant     *store.Tenant
	user       *store.User
	client     *store.Client
	connection *store.Connection
}

// PhoneActionBound reports whether trigger has a deployed, bound Action.
func (e *Engine) PhoneActionBound(ctx context.Context, tid, trigger string) (bool, error) {
	bound, err := e.Store.Actions().Bindings(ctx, tid, trigger)
	return len(bound) > 0, err
}

// RunPhoneAction implements phone.ActionRunner.
func (e *Engine) RunPhoneAction(ctx context.Context, tid string, in phone.ActionInput) error {
	pi := PhoneInput{Tenant: tid, Message: in.Message, MessageType: in.MessageType, AsText: in.AsText, AsVoice: in.AsVoice,
		ConnectionID: in.Route.ConnectionID,
		Request:      RequestInfo{IP: in.Request.IP, UserAgent: in.Request.UserAgent, Language: in.Request.Language, Hostname: in.Request.Hostname}}
	switch in.Trigger {
	case TriggerCustomPhoneProvider:
		return e.RunPhoneProvider(ctx, pi)
	case TriggerSendPhoneMessage:
		return e.RunSendPhoneMessage(ctx, pi)
	}
	return &phone.SendError{Class: phone.ClassProviderAuth, Err: fmt.Errorf("unknown phone trigger %q", in.Trigger)}
}

// RunPhoneProvider runs the custom-phone-provider flow once, synchronously.
// api.notification.retry accepts the message and queues the documented
// retries as durable jobs; a drop, a thrown error, a timeout or an
// unavailable runner is a delivery failure (D-0060 LR3).
func (e *Engine) RunPhoneProvider(ctx context.Context, in PhoneInput) error {
	return e.runPhone(ctx, TriggerCustomPhoneProvider, in)
}

// RunSendPhoneMessage runs the blocking send-phone-message flow (Guardian
// phone-message-hook). It has no retries.
func (e *Engine) RunSendPhoneMessage(ctx context.Context, in PhoneInput) error {
	return e.runPhone(ctx, TriggerSendPhoneMessage, in)
}

func (e *Engine) runPhone(ctx context.Context, trigger string, in PhoneInput) error {
	transient := func(err error) error { return &phone.SendError{Class: phone.ClassTransient, Err: err} }
	bound, err := e.Store.Actions().Bindings(ctx, in.Tenant, trigger)
	if err != nil {
		return transient(errors.New("phone Action bindings unavailable"))
	}
	if len(bound) == 0 {
		return &phone.SendError{Class: phone.ClassProviderAuth, Err: phone.ErrActionUnbound}
	}
	sensitive := map[string]string{}
	// The spoken (digit-separated) forms in as_voice and voice text are as
	// secret as the code itself.
	for i, form := range phone.CodeForms(in.Message.Code) {
		ctx = logscrub.WithCredentials(ctx, form)
		logs.AddCredentials(ctx, form)
		sensitive[fmt.Sprint("code", i)] = form
	}
	snap, err := e.phoneSnapshot(ctx, &in)
	if err != nil {
		return transient(errors.New("phone Action context unavailable"))
	}
	f := &flow{tenantID: in.Tenant, trigger: trigger, handler: handlerFor(trigger), hostname: snap.tenant.CanonicalHost, units: pinned(bound),
		acc: newAccum(trigger, nil, nil, false), cache: e.caches.get(in.Tenant, trigger), redactor: customdb.NewRedactor(sensitive)}
	f.event = func() map[string]any { return phoneEvent(trigger, snap, f.acc) }
	result, err := e.run(ctx, f, nil)
	if f.dropped != nil {
		return transient(errors.New("the phone Action dropped the message"))
	}
	if err != nil {
		return transient(fmt.Errorf("phone Action failed: %s", errorID(err)))
	}
	if n := result.Notification; trigger == TriggerCustomPhoneProvider && n != nil && n.Kind == "retry" && phoneRetries > 0 {
		job := AsyncJob{TenantID: in.Tenant, Trigger: trigger, Input: phoneEvent(trigger, snap, newAccum(trigger, nil, nil, false)), NotBefore: e.now().Add(retryDelays[0])}
		if err := e.Store.WithTx(ctx, func(tx store.Store) error { return e.Enqueue(ctx, tx, job) }); err != nil {
			return transient(fmt.Errorf("phone retry could not be queued: %w", err))
		}
	}
	return nil
}

func (e *Engine) phoneSnapshot(ctx context.Context, in *PhoneInput) (*phoneSnapshot, error) {
	s := &phoneSnapshot{in: in}
	t, err := e.Store.Tenants().Get(ctx, in.Tenant)
	if err != nil {
		return nil, err
	}
	s.tenant = t
	if id := in.Message.UserID; id != "" {
		if s.user, err = e.Store.Users().Get(ctx, in.Tenant, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if id := in.Message.ClientID; id != "" {
		if s.client, err = e.Store.Clients().Get(ctx, in.Tenant, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if id := in.ConnectionID; id != "" {
		if s.connection, err = e.Store.Connections().Get(ctx, in.Tenant, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	return s, nil
}
