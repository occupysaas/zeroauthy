package grpcstore

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Temporary until this driver implements refresh_tokens_ii.v1.
type refreshIIUnavailable struct{}

func (*Client) DPoP() store.DPoP               { return refreshIIUnavailable{} }
func (*Client) TokenQuotas() store.TokenQuotas { return refreshIIUnavailable{} }
func (refreshIIUnavailable) UseProof(context.Context, string, string, string, string, time.Time, time.Time) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (refreshIIUnavailable) PurgeBefore(context.Context, time.Time, int) (int, error) {
	return 0, store.ErrRefreshTokensIIUnavailable
}
func (refreshIIUnavailable) Consume(context.Context, string, []store.QuotaSubject, time.Time) ([]store.QuotaState, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
func (refreshIIUnavailable) Peek(context.Context, string, []store.QuotaSubject, time.Time) ([]store.QuotaState, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) ConvertNonRotating(context.Context, string, string, *store.RefreshToken) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) ConvertRotating(context.Context, string, string, *store.RefreshToken, time.Time, time.Duration) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) RevokeByUserClient(context.Context, string, string, string, string, time.Time) (int, error) {
	return 0, store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) RevokeBySession(context.Context, string, string, time.Time) (int, error) {
	return 0, store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) ListByUserPage(context.Context, string, string, string, string, int) ([]*store.RefreshToken, string, error) {
	return nil, "", store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) UpdateMetadata(context.Context, string, string, map[string]string) (*store.RefreshToken, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
func (clientRefreshTokens) RecordExchange(context.Context, string, string, string, string, time.Time) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (clientSessions) UpdateMetadata(context.Context, string, string, map[string]string) (*store.LoginSession, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
