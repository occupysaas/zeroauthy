package sqlstore

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Temporary until this driver implements refresh_tokens_ii.v1.
type refreshIIUnavailable struct{}

func (*Store) DPoP() store.DPoP               { return refreshIIUnavailable{} }
func (*Store) TokenQuotas() store.TokenQuotas { return refreshIIUnavailable{} }
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
func (refreshTokens) ConvertNonRotating(context.Context, string, string, *store.RefreshToken) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) ConvertRotating(context.Context, string, string, *store.RefreshToken, time.Time, time.Duration) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) RevokeByUserClient(context.Context, string, string, string, string, time.Time) (int, error) {
	return 0, store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) RevokeBySession(context.Context, string, string, time.Time) (int, error) {
	return 0, store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) ListByUserPage(context.Context, string, string, string, string, int) ([]*store.RefreshToken, string, error) {
	return nil, "", store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) UpdateMetadata(context.Context, string, string, map[string]string) (*store.RefreshToken, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
func (refreshTokens) RecordExchange(context.Context, string, string, string, string, time.Time) error {
	return store.ErrRefreshTokensIIUnavailable
}
func (sessions) UpdateMetadata(context.Context, string, string, map[string]string) (*store.LoginSession, error) {
	return nil, store.ErrRefreshTokensIIUnavailable
}
