package myorg

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// listUserStores lists the organization's enabled database connections
// (LR42b-7): where invited members sign up.
func (h *Handlers) listUserStores(w http.ResponseWriter, r *http.Request, c *Caller) {
	ctx := r.Context()
	out := []any{}
	from := ""
	for {
		res, err := h.Store.Organizations().Connections(ctx, c.TenantID, c.Org.ID, store.OrgPage{From: from, Take: 100})
		if err != nil {
			h.fail(w, r, "list user stores", err)
			return
		}
		for _, oc := range res.Items {
			conn, err := h.Store.Connections().Get(ctx, c.TenantID, oc.ConnectionID)
			if err != nil || conn.Strategy != store.StrategyDatabase {
				continue
			}
			level := oc.OrganizationAccessLevel
			if level == "" {
				level = "none"
			}
			display, _ := conn.Extra["display_name"].(string)
			if display == "" {
				display = conn.Name
			}
			out = append(out, map[string]any{"id": conn.ID, "name": conn.Name, "display_name": display, "access_level": level, "is_enabled": oc.IsEnabled})
		}
		if res.Next == "" {
			break
		}
		from = res.Next
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"user_stores": out})
}
