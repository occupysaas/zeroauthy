package mgmt

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

// GetPhoneProviderProtection reads the SMS send policy. It is always
// available and reads {type: default} when never set (D-0060 P14).
func (h *Handlers) GetPhoneProviderProtection(w http.ResponseWriter, r *http.Request) {
	t, err := h.Store.Tenants().Get(r.Context(), resolved(r).ID)
	if err != nil {
		h.failTx(w, r, "get phone provider protection", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"type": tenantrules.PhoneSettingsOf(t).ProviderProtection})
}

func (h *Handlers) UpdatePhoneProviderProtection(w http.ResponseWriter, r *http.Request) {
	raw, err := decodePhoneProviderBody(r, "type")
	if err != nil {
		Fail(w, err)
		return
	}
	var typ string
	if json.Unmarshal(raw["type"], &typ) != nil || !slices.Contains(tenantrules.ProtectionTypes, typ) {
		Fail(w, badBody("type must be exponential or default"))
		return
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		current, err := tx.Tenants().Get(r.Context(), resolved(r).ID)
		if err != nil {
			return err
		}
		if current.Reserved {
			return errSystemTenant
		}
		return tx.Tenants().Update(r.Context(), tenantrules.WithProviderProtection(current, typ))
	})
	if err != nil {
		h.failTx(w, r, "update phone provider protection", err)
		return
	}
	logDetails(r, "update phone provider protection", "type", typ)
	writeJSON(w, http.StatusOK, map[string]any{"type": typ})
}
