package mgmt

import (
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// UserBlocks resolves aliases inside the transaction so linked identities and
// concurrent deletes cannot turn a narrow unblock into a broader mutation.
func (h *Handlers) UserBlocks(w http.ResponseWriter, r *http.Request, userID string) {
	identifier := loginid.Normalize(r.URL.Query().Get("identifier"))
	if userID != "" && !validUserID(userID) {
		Fail(w, badUserID(userID))
		return
	}
	if userID == "" && (identifier == "" || !storableText(identifier)) {
		Fail(w, badQuery("identifier is required"))
		return
	}
	consider := false
	if r.Method == "GET" {
		if raw, ok := r.URL.Query()["consider_brute_force_enablement"]; ok {
			var err error
			if len(raw) != 1 {
				Fail(w, badQuery("invalid consider_brute_force_enablement"))
				return
			}
			consider, err = strconv.ParseBool(raw[0])
			if err != nil {
				Fail(w, badQuery("invalid consider_brute_force_enablement"))
				return
			}
		}
	}
	rows := []map[string]string{}
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		tenantID := resolved(r).ID
		connections, _, err := tx.Connections().List(r.Context(), tenantID, store.ConnectionFilter{}, store.Page{})
		if err != nil {
			return err
		}
		byID := map[string]*store.Connection{}
		byName := map[string]*store.Connection{}
		for _, c := range connections {
			byID[c.ID] = c
			byName[c.Name] = c
		}
		filters := map[store.ProtectionFilter]bool{}
		addIdentity := func(u *store.User, id *store.Identity) {
			c := byName[id.Connection]
			if c == nil || c.Strategy != store.StrategyDatabase {
				return
			}
			email, username := u.IdentityLogin(id)
			for _, alias := range []string{protection.IdentityIdentifier(u, id), email, username} {
				if alias != "" {
					filters[store.ProtectionFilter{Kind: store.ProtectionBruteForce, ConnectionID: c.ID, Identifier: loginid.Normalize(alias)}] = true
				}
			}
		}
		if userID != "" {
			u, e := tx.Users().Get(r.Context(), tenantID, userID)
			if errors.Is(e, store.ErrNotFound) {
				return errUserNotFound
			}
			if e != nil {
				return e
			}
			for i := range u.Identities {
				addIdentity(u, &u.Identities[i])
			}
		} else {
			// Raw unknown identifiers remain queryable without a persisted account.
			filters[store.ProtectionFilter{Kind: store.ProtectionBruteForce, Identifier: identifier}] = true
			for _, c := range connections {
				if c.Strategy != store.StrategyDatabase {
					continue
				}
				u, e := tx.Users().FindByLogin(r.Context(), tenantID, c.Name, identifier)
				if errors.Is(e, store.ErrNotFound) {
					continue
				}
				if e != nil {
					return e
				}
				if id := u.IdentityByLogin(c.Name, identifier); id != nil {
					addIdentity(u, id)
				}
			}
		}
		enabled := true
		if consider {
			t, e := tx.Tenants().Get(r.Context(), tenantID)
			if e != nil {
				return e
			}
			enabled = tenantProtection(t).BruteForce.Enabled
		}
		seen := map[store.ProtectionKey]bool{}
		now := h.now()
		for f := range filters {
			if r.Method == "DELETE" {
				if e := tx.Protection().Clear(r.Context(), tenantID, f); e != nil {
					return e
				}
				continue
			}
			blocks, e := tx.Protection().Blocks(r.Context(), tenantID, f, now)
			if e != nil {
				return e
			}
			for _, b := range blocks {
				c := byID[b.Key.ConnectionID]
				if seen[b.Key] || consider && (!enabled || c == nil || !c.BruteForceProtection) {
					continue
				}
				seen[b.Key] = true
				row := map[string]string{"identifier": b.Key.Identifier}
				if b.Key.IP != "" {
					row["ip"] = b.Key.IP
				}
				if c != nil {
					row["connection"] = c.Name
				}
				rows = append(rows, row)
			}
		}
		return nil
	})
	if err != nil {
		h.failTx(w, r, "user automatic blocks", err)
		return
	}
	if r.Method == "DELETE" {
		h.audit(r, "clear user automatic blocks")
		w.WriteHeader(204)
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		for _, k := range []string{"connection", "identifier", "ip"} {
			if rows[i][k] != rows[j][k] {
				return rows[i][k] < rows[j][k]
			}
		}
		return false
	})
	writeJSON(w, 200, map[string]any{"blocked_for": rows})
}

// IPBlock exposes suspicious-IP stages only; brute-force and reset-mail state
// are deliberately outside the selected repository filters.
func (h *Handlers) IPBlock(w http.ResponseWriter, r *http.Request, raw string) {
	ip := protection.CanonicalIP(raw)
	if ip == "unknown" {
		Fail(w, &Error{Status: 400, Code: "invalid_uri", Message: "Invalid IP address"})
		return
	}
	blocked := false
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		for _, kind := range []string{store.ProtectionSuspiciousIPLogin, store.ProtectionSuspiciousIPRegistration} {
			f := store.ProtectionFilter{Kind: kind, IP: ip}
			if r.Method == "DELETE" {
				if err := tx.Protection().Clear(r.Context(), resolved(r).ID, f); err != nil {
					return err
				}
			} else {
				bs, err := tx.Protection().Blocks(r.Context(), resolved(r).ID, f, h.now())
				if err != nil {
					return err
				}
				blocked = blocked || len(bs) > 0
			}
		}
		return nil
	})
	if err != nil {
		h.failTx(w, r, "IP automatic blocks", err)
		return
	}
	if r.Method == "DELETE" {
		h.audit(r, "clear IP automatic blocks")
		w.WriteHeader(204)
		return
	}
	if !blocked {
		WriteError(w, 404, "", "Not Found")
		return
	}
	w.WriteHeader(200)
}
