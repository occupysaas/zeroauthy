package mfa

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/email"
)

func (s *Service) sendEmail(ctx context.Context, tid, uid, code string) error {
	if s.mail == nil {
		return ErrEmailDelivery
	}
	ctx = s.operationContext(ctx, code)
	if err := s.mail.Send(ctx, email.Event{TenantID: tid, UserID: uid, Template: "mfa_oob_code", Variables: map[string]any{"code": code, "expires_in": 300}}); err != nil {
		return ErrEmailDelivery
	}
	s.emit(ctx, tid, uid, "gd_send_email")
	return nil
}
