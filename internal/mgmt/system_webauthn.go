package mgmt

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// consoleMethodJSON deliberately reads only the metadata needed by operators.
// Never serialize a Management method response and discard secrets in a browser.
func consoleMethodJSON(r *http.Request, a store.Authenticator) map[string]any {
	a = publicPhone(r, a)
	out := map[string]any{"id": a.ID, "type": a.Type, "name": a.Name, "created_at": userTime(a.CreatedAt)}
	if !a.LastAuthAt.IsZero() {
		out["last_auth_at"] = userTime(a.LastAuthAt)
	}
	if a.Type == "phone" {
		out["phone_number"] = a.Phone
	}
	if a.Type == "passkey" || a.Type == "webauthn-roaming" || a.Type == "webauthn-platform" {
		out["relying_party_identifier"] = a.RPID
	}
	if a.Type == "passkey" {
		var data struct {
			AAGUID string `json:"aaguid"`
			BE     bool   `json:"backup_eligible"`
			BS     bool   `json:"backed_up"`
		}
		_ = json.Unmarshal(a.PublicData, &data)
		out["aaguid"] = data.AAGUID
		out["credential_device_type"] = "single_device"
		if data.BE {
			out["credential_device_type"] = "multi_device"
		}
		out["credential_backed_up"] = data.BS
	}
	return out
}

// ConsoleAuthenticationMethods is a system-only allowlisted display projection.
func (h *Handlers) ConsoleAuthenticationMethods(w http.ResponseWriter, r *http.Request, name, uid, id string) {
	tn := h.executionTenant(w, r, name)
	if tn == nil {
		return
	}
	res, _ := tenant.FromContext(r.Context())
	res.Tenant = tn
	r = r.WithContext(tenant.WithResolved(r.Context(), res))
	if _, err := h.Store.Users().Get(r.Context(), tn.ID, uid); err != nil {
		h.mfaFail(w, r, err)
		return
	}
	if r.Method == http.MethodGet {
		all, err := h.Store.MFA().ListAuthenticators(r.Context(), tn.ID, uid)
		if err != nil {
			h.mfaFail(w, r, err)
			return
		}
		out := []any{}
		for _, a := range all {
			out = append(out, consoleMethodJSON(r, a))
		}
		writeJSON(w, 200, out)
		return
	}
	body, err := mfaBody(r, map[string]any{"type": "object", "additionalProperties": false, "required": []any{"name"}, "properties": map[string]any{"name": map[string]any{"type": "string", "minLength": 1, "maxLength": 20}}})
	if err != nil {
		Fail(w, err)
		return
	}
	var out map[string]any
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		current, e := tx.Tenants().Get(r.Context(), tn.ID)
		if e != nil {
			return e
		}
		if current.Reserved {
			return errSystemTenant
		}
		if _, e = tx.Users().GetForUpdate(r.Context(), tn.ID, uid); e != nil {
			return e
		}
		a, e := tx.MFA().GetAuthenticator(r.Context(), tn.ID, uid, id)
		if e != nil {
			return e
		}
		a.Name = body.(map[string]any)["name"].(string)
		if e = tx.MFA().UpdateAuthenticator(r.Context(), a); e != nil {
			return e
		}
		out = consoleMethodJSON(r, *a)
		return nil
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

// RelyingPartyIds uses the same resolver and deployment policy as ceremonies.
func (h *Handlers) RelyingPartyIds(w http.ResponseWriter, r *http.Request, name string) {
	tn := h.executionTenant(w, r, name)
	if tn == nil {
		return
	}
	domains, err := h.Store.CustomDomains().List(r.Context(), tn.ID)
	if err != nil {
		Fail(w, internalError(h, r, "list relying party hosts", err))
		return
	}
	hosts := map[string]*store.CustomDomain{tn.CanonicalHost: nil}
	for _, host := range tn.Domains {
		hosts[host] = nil
	}
	for _, domain := range domains {
		hosts[domain.Domain] = domain
	}
	names := make([]string, 0, len(hosts))
	for host := range hosts {
		if host != "" {
			names = append(names, host)
		}
	}
	sort.Strings(names)
	out := []any{}
	for _, host := range names {
		result, e := h.rpidPolicy().For(r.Context(), tenant.Resolved{Tenant: tn, Host: host})
		if e != nil {
			Fail(w, internalError(h, r, "resolve relying party host", e))
			return
		}
		item := map[string]any{"host": host, "origin": result.Origin, "kind": result.Kind, "relying_party_identifier": result.RPID, "valid": result.Valid}
		if d := hosts[host]; d != nil {
			item["kind"] = rpid.KindCustom
			item["custom_domain_id"] = d.ID
			// An inactive domain is unusable. Retain its configured RP ID for repair.
			if !result.Valid {
				if d.RelyingPartyIdentifier != "" {
					item["relying_party_identifier"] = d.RelyingPartyIdentifier
				}
			}
		}
		out = append(out, item)
	}
	writeJSON(w, 200, out)
}
