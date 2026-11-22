package oauth

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Record only after the exchange succeeds, in its mint transaction. Conversion
// removes or revokes the old presentation; rotation retains its history.
func (h *Handlers) recordRefreshExchange(ctx context.Context, repo store.RefreshTokens, old *store.RefreshToken, nextRaw string) error {
	ri := requestInfoFrom(ctx)
	now := h.now().UTC()
	current, err := repo.Get(ctx, old.TenantID, old.ID)
	if err != nil && (!errors.Is(err, store.ErrNotFound) || nextRaw == "") {
		return err
	}
	if err == nil && current.RevokedAt != nil && nextRaw == "" {
		return store.ErrNotFound
	}
	if err == nil && current.RevokedAt == nil {
		if e := repo.RecordExchange(ctx, old.TenantID, old.ID, ri.IP, ri.UserAgent, now); e != nil {
			return e
		}
	}
	if nextRaw != "" {
		next, e := repo.GetByTokenHash(ctx, old.TenantID, secrets.HashToken(nextRaw))
		if e != nil {
			return e
		}
		return repo.RecordExchange(ctx, old.TenantID, next.ID, ri.IP, ri.UserAgent, now)
	}
	return nil
}
