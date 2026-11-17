package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const PendingCookiePrefix = "za_pending_login_"
const PendingIdentityParam = "za_pending_identity"
const MaxPendingLogins = 8

func pendingCookieID(name string) string {
	id, ok := strings.CutPrefix(name, PendingCookiePrefix)
	if !ok || len(id) == 0 || len(id) > 128 {
		return ""
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ""
		}
	}
	return id
}
func PendingCookieCount(r *http.Request) int {
	n := 0
	for _, c := range r.Cookies() {
		if pendingCookieID(c.Name) != "" {
			n++
		}
	}
	return n
}

// EndPending revokes only credentials actually proved by this browser on this
// origin. Stale tabs cannot reuse their cookies after a completed local logout.
func (m *Manager) EndPending(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant) error {
	var cleared []string
	err := m.Store.WithTx(ctx, func(tx store.Store) error {
		for _, c := range r.Cookies() {
			id := pendingCookieID(c.Name)
			if id == "" {
				continue
			}
			txn, err := tx.AuthTransactions().Get(ctx, t.ID, id)
			if errors.Is(err, store.ErrNotFound) {
				cleared = append(cleared, c.Name)
				continue
			}
			if err != nil {
				return err
			}
			var s store.LoginSession
			if txn.Origin != requestOrigin(r) || json.Unmarshal([]byte(txn.Params[PendingIdentityParam]), &s) != nil || s.TenantID != t.ID || !sameOrigin(r, &s) || s.TokenHash != secrets.HashToken(c.Value) {
				continue
			}
			if err = tx.AuthTransactions().Delete(ctx, t.ID, id); err != nil {
				return err
			}
			cleared = append(cleared, c.Name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range cleared {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	return nil
}
