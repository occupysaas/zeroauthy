package myaccount

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// guardianFactors maps Guardian factor toggles to My Account factor types,
// in listing order. push-notification is not offered (LR42a-2).
var guardianFactors = []struct{ guardian, typ string }{
	{"webauthn-platform", "webauthn-platform"}, {"webauthn-roaming", "webauthn-roaming"},
	{"otp", "totp"}, {"sms", "phone"}, {"email", "email"}, {"recovery-code", "recovery-code"},
}

type factor struct {
	Type  string   `json:"type"`
	Usage []string `json:"usage"`
}

// factors lists what the user may enroll: password for database users,
// passkey when one of the user's database connections allows passkeys,
// then the enabled Guardian factors (Y9).
func (h *Handlers) factors(ctx context.Context, u *store.User) ([]factor, error) {
	out := []factor{}
	conns, err := h.databaseConnections(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(conns) > 0 {
		out = append(out, factor{"password", []string{"primary"}})
	}
	if ok, err := h.passkeysAllowed(ctx, u.TenantID, conns); err != nil {
		return nil, err
	} else if ok {
		out = append(out, factor{"passkey", []string{"primary"}})
	}
	g, err := h.Store.MFA().GetGuardian(ctx, u.TenantID)
	if err != nil {
		return nil, err
	}
	for _, f := range guardianFactors {
		if g.Factors[f.guardian] {
			out = append(out, factor{f.typ, []string{"secondary"}})
		}
	}
	return out, nil
}

// databaseConnections are the database connections of u's identities.
func (h *Handlers) databaseConnections(ctx context.Context, u *store.User) ([]*store.Connection, error) {
	out := []*store.Connection{}
	for _, id := range u.Identities {
		if id.Provider != store.StrategyDatabase {
			continue
		}
		conn, err := h.Store.Connections().GetByName(ctx, u.TenantID, id.Connection)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, conn)
	}
	return out, nil
}

func (h *Handlers) passkeysAllowed(ctx context.Context, tid string, conns []*store.Connection) (bool, error) {
	if len(conns) == 0 {
		return false, nil
	}
	if ok, err := store.WebAuthnAvailable(ctx, h.Store); err != nil || !ok {
		return false, err
	}
	var prompts map[string]any
	cfg, err := h.Store.HostedLogins().Get(ctx, tid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if cfg != nil {
		prompts = cfg.Prompts
	}
	for _, conn := range conns {
		if p, _ := connrules.Passkeys(conn, prompts); p.Effective {
			return true, nil
		}
	}
	return false, nil
}

func (h *Handlers) listFactors(w http.ResponseWriter, r *http.Request, c *Caller) {
	out, err := h.factors(r.Context(), c.User)
	if err != nil {
		h.fail(w, r, "list factors", err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"factors": out})
}
