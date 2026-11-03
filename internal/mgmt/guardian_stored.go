package mgmt

import (
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"strings"
)

// The secret envelope is bound to both tenant and the exact provider route;
// SMS and phone remain independently extensible JSON configuration records.
func (h *Handlers) guardianStored(w http.ResponseWriter, r *http.Request, route mfarules.RouteSchema, body any) {
	path := route.Path
	out := map[string]any{}
	if route.Method == "GET" {
		g, err := h.Store.MFA().GetGuardian(r.Context(), resolved(r).ID)
		if err != nil {
			h.mfaFail(w, r, err)
			return
		}
		if raw := g.Stored[path]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &out)
		} else {
			for _, rr := range mfarules.Inventory().Routes {
				if rr.Path != path || rr.Method != "PUT" {
					continue
				}
				props, _ := rr.Body["properties"].(map[string]any)
				for key, v := range props {
					p, _ := v.(map[string]any)
					if p["writeOnly"] == true {
						continue
					}
					if val, ok := p["default"]; ok {
						out[key] = val
					}
				}
			}
		}
		writeJSON(w, 200, out)
		return
	}
	patch := body.(map[string]any)
	err := h.guardianWrite(r, func(g *store.GuardianSettings) error {
		public := map[string]any{}
		private := map[string]any{}
		if raw := g.Stored[path]; r.Method == "PATCH" && len(raw) > 0 {
			if json.Unmarshal(raw, &public) != nil {
				return store.ErrInvalid
			}
		}
		// Omitted secret fields retain their old values even on PUT. They are
		// write-only, so clients cannot read them in order to send them back.
		if blob := g.SealedSecrets[path]; len(blob) > 0 {
			raw, e := keys.OpenBound(h.Wrapper, "guardian-provider/v1", []string{g.TenantID, path}, blob)
			if e != nil {
				return e
			}
			if json.Unmarshal(raw, &private) != nil {
				return store.ErrInvalid
			}
		}
		props, _ := route.Body["properties"].(map[string]any)
		for k, v := range patch {
			schema, _ := props[k].(map[string]any)
			if schema["writeOnly"] == true {
				if v == nil {
					delete(private, k)
				} else {
					private[k] = v
				}
			} else {
				public[k] = v
			}
		}
		raw, e := json.Marshal(public)
		if e != nil {
			return e
		}
		g.Stored[path] = raw
		out = public
		if len(private) > 0 {
			raw, e = json.Marshal(private)
			if e != nil {
				return e
			}
			g.SealedSecrets[path], e = keys.SealBound(h.Wrapper, "guardian-provider/v1", []string{g.TenantID, path}, raw)
			return e
		}
		delete(g.SealedSecrets, path)
		return nil
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	code := "gd_tenant_update"
	if strings.Contains(path, "/sms/") || strings.Contains(path, "/phone/") {
		code = "gd_phone_settings_update"
	}
	if strings.Contains(path, "/email/") {
		code = "gd_email_settings_update"
	}
	h.domainEvent(r, code, nil, nil, nil)
	logDetails(r, "update Guardian configuration", "route", path)
	writeJSON(w, 200, out)
}
