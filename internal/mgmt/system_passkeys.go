package mgmt

import (
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// PasskeyPrerequisites exposes the computed policy to operators. Connection
// lookup includes the target tenant so foreign IDs cannot disclose policy.
func (h *Handlers) PasskeyPrerequisites(w http.ResponseWriter, r *http.Request, tenantName, id string) {
	tn, err := h.Store.Tenants().GetByName(r.Context(), tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get passkey prerequisites", err))
		return
	}
	conn, err := h.Store.Connections().Get(r.Context(), tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get passkey prerequisites", err))
		return
	}
	cfg, err := h.Store.HostedLogins().Get(r.Context(), tn.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		Fail(w, internalError(h, r, "get passkey prerequisites", err))
		return
	}
	var prompts map[string]any
	if cfg != nil {
		prompts = cfg.Prompts
	}
	policy, unmet := connrules.Passkeys(conn, prompts)
	writeJSON(w, http.StatusOK, map[string]any{"effective": policy.Effective, "unmet": unmet})
}

// RoamingUVSettings is an operator system extension; it has no v2 equivalent.
func (h *Handlers) RoamingUVSettings(w http.ResponseWriter, r *http.Request, tenantName string) {
	tn, err := h.Store.Tenants().GetByName(r.Context(), tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, err)
		return
	}
	if r.Method == http.MethodGet {
		g, e := h.Store.MFA().GetGuardian(r.Context(), tn.ID)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		writeJSON(w, 200, map[string]string{"user_verification": mfa.RoamingUV(g)})
		return
	}
	body, err := mfaBody(r, map[string]any{"type": "object", "additionalProperties": false, "required": []any{"user_verification"}, "properties": map[string]any{"user_verification": map[string]any{"type": "string", "enum": []any{"discouraged", "preferred", "required"}}}})
	if err != nil {
		Fail(w, err)
		return
	}
	uv := body.(map[string]any)["user_verification"].(string)
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		current, e := tx.Tenants().Get(r.Context(), tn.ID)
		if e != nil {
			return e
		}
		if current.Reserved {
			return errSystemTenant
		}
		g, e := tx.MFA().GetGuardian(r.Context(), tn.ID)
		if e != nil {
			return e
		}
		if g.Stored == nil {
			g.Stored = map[string]json.RawMessage{}
		}
		g.Stored["webauthn-roaming/settings"], _ = json.Marshal(map[string]string{"user_verification": uv})
		return tx.MFA().PutGuardian(r.Context(), g, g.Version)
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	res, _ := tenant.FromContext(r.Context())
	res.Tenant = tn
	h.domainEvent(r.WithContext(tenant.WithResolved(r.Context(), res)), "gd_tenant_update", nil, nil, nil)
	writeJSON(w, 200, map[string]string{"user_verification": uv})
}
