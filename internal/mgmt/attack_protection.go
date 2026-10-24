package mgmt

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func publicProtection(p store.ProtectionSettings, feature string) any {
	switch feature {
	case "brute-force-protection":
		return p.BruteForce
	case "suspicious-ip-throttling":
		return p.SuspiciousIP
	case "breached-password-detection":
		return p.BreachedPassword
	case "bot-detection":
		return p.Bot
	default:
		return keys.PublicCAPTCHA(p.CAPTCHA)
	}
}
func tenantProtection(t *store.Tenant) store.ProtectionSettings {
	if !t.ProtectionSettingsInitialized {
		return protectionrules.Defaults()
	}
	return t.ProtectionSettings
}

// GetProtection always reads fresh persisted settings and explicitly redacts CAPTCHA.
func (h *Handlers) GetProtection(w http.ResponseWriter, r *http.Request, feature string) {
	t, err := h.Store.Tenants().Get(r.Context(), resolved(r).ID)
	if err != nil {
		h.failTx(w, r, "get attack protection", err)
		return
	}
	writeJSON(w, 200, publicProtection(tenantProtection(t), feature))
}
func (h *Handlers) UpdateProtection(w http.ResponseWriter, r *http.Request, feature string) {
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	patch := make(map[string]any, len(raw))
	for k, v := range raw {
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		var x any
		if err = d.Decode(&x); err != nil {
			Fail(w, badBody("invalid JSON"))
			return
		}
		patch[k] = x
	}
	var out store.ProtectionSettings
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		current, e := tx.Tenants().Get(r.Context(), resolved(r).ID)
		if e != nil {
			return e
		}
		if current.Reserved {
			return errSystemTenant
		}
		if feature == "captcha" {
			out, e = keys.PatchCAPTCHA(h.Wrapper, current.ID, tenantProtection(current), patch)
		} else {
			out, e = protectionrules.Apply(tenantProtection(current), feature, patch)
		}
		if e != nil {
			return badBody("%s", e)
		}
		current.ProtectionSettings = out
		current.ProtectionSettingsInitialized = true
		// Store Update invalidates precisely the generations affected by algorithm,
		// key-mode, threshold increases or rate changes, inside this transaction.
		return tx.Tenants().Update(r.Context(), current)
	})
	if err != nil {
		h.failTx(w, r, "update attack protection", err)
		return
	}
	h.audit(r, "update attack protection "+feature)
	writeJSON(w, 200, publicProtection(out, feature))
}
