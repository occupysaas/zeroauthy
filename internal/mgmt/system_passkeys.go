package mgmt

import (
	"errors"
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
