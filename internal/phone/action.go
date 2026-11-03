package phone

import (
	"context"
	"errors"
)

// Phone Action triggers (D-0060). custom-phone-provider backs the branding
// provider named "custom"; send-phone-message backs Guardian's
// "phone-message-hook".
const (
	TriggerCustomPhoneProvider = "custom-phone-provider"
	TriggerSendPhoneMessage    = "send-phone-message"
)

// ErrActionUnbound reports an Action-backed provider without a deployed,
// bound Action: the provider does not work (D-0060 LR3).
var ErrActionUnbound = errors.New("phone: no deployed phone Action is bound")

// Request is the end-user request behind a send. It feeds the Action
// event's request and the SMS gateway's forward_req_info; never logged.
type Request struct {
	IP, UserAgent, Language, Hostname string
}

type requestKey struct{}

// WithRequest attaches the end-user request to ctx for the dispatcher.
func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// RequestFrom returns the request attached by WithRequest.
func RequestFrom(ctx context.Context) Request {
	r, _ := ctx.Value(requestKey{}).(Request)
	return r
}

// ActionInput is one hand-off to a phone Action. Message.Code reaches the
// Action event only; the runner masks it in console output and records.
type ActionInput struct {
	Trigger string
	Route   Route
	Message Message
	// MessageType is the template type (otp_verify, otp_enroll, ...).
	MessageType string
	// AsText and AsVoice are both rendered bodies (custom-phone-provider).
	AsText, AsVoice string
	Request         Request
}

// ActionRunner runs phone Actions. Implemented by the Actions engine.
type ActionRunner interface {
	// PhoneActionBound reports whether trigger has a deployed, bound Action.
	PhoneActionBound(ctx context.Context, tid, trigger string) (bool, error)
	// RunPhoneAction runs one attempt. Failures are *SendError (transient
	// for Action errors, drops and an unavailable runner) or ErrActionUnbound.
	RunPhoneAction(ctx context.Context, tid string, in ActionInput) error
}

// actionSender adapts an ActionRunner to Sender. The message body serves as
// both rendered forms; the dispatcher calls the runner directly to pass
// both template bodies.
type actionSender struct {
	runner  ActionRunner
	trigger string
}

// NewActionSender returns the Sender of an Action-backed provider.
func NewActionSender(r ActionRunner, trigger string) Sender {
	return &actionSender{runner: r, trigger: trigger}
}

func (a *actionSender) Send(ctx context.Context, m Message) (Result, error) {
	if a.runner == nil {
		return Result{}, &SendError{Class: ClassTransient, Err: ErrActionUnbound}
	}
	typ := m.Type
	if typ == "passwordless" {
		typ = "otp_verify"
	}
	in := ActionInput{Trigger: a.trigger, Message: m, MessageType: typ, AsText: m.Body, AsVoice: m.Body, Request: RequestFrom(ctx)}
	if err := a.runner.RunPhoneAction(ctx, m.TenantID, in); err != nil {
		return Result{}, err
	}
	return Result{}, nil
}
