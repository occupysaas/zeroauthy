package mgmt

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) GetBranding(w http.ResponseWriter, r *http.Request) {
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	b := c.Branding
	if b == nil {
		b = map[string]any{}
	}
	writeJSON(w, http.StatusOK, b)
}

func (h *Handlers) UpdateBranding(w http.ResponseWriter, r *http.Request) {
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("branding body is too large"))
		return
	}
	h.mutateHosted(w, r, "update branding", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "branding", raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, c.Branding) })
}
