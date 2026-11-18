package login

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identifiercode"
)

func (h *Handlers) identifierCodes() identifiercode.Service {
	s := identifiercode.Service{Store: h.Store, Email: h.codeEmail(), Recorder: h.Recorder, Now: h.now}
	if h.Authz != nil {
		s.Wrapper = h.Authz.Wrapper
	}
	if h.MFA != nil {
		s.Phone = h.MFA.Phone
	}
	return s
}

func (h *Handlers) sendIdentifierCode(ctx context.Context, tid, conn, number, kind, payload string) error {
	return h.identifierCodes().Send(ctx, identifiercode.SendInput{
		TenantID: tid, ConnectionID: conn, Identifier: number, Kind: kind, Payload: payload,
	})
}

func (h *Handlers) consumeIdentifierCode(ctx context.Context, tid, conn, number, kind, code string) (string, error) {
	return h.identifierCodes().Consume(ctx, tid, conn, number, kind, code)
}

func (h *Handlers) codeEmail() *email.Service {
	if h.Resets != nil && h.Resets.Email != nil {
		return h.Resets.Email
	}
	if h.Verification != nil {
		return h.Verification.Email
	}
	return nil
}
func (h *Handlers) codeTemplateEnabled(ctx context.Context, tid, name string) bool {
	svc := h.codeEmail()
	if svc == nil {
		return false
	}
	p, err := svc.Resolve(ctx, tid, name)
	return err == nil && p.Template != nil && p.Enabled
}
