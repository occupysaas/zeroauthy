package brandingrules

import (
	"encoding/json"
	"os"
	"testing"
)

// A missing entry would let an implemented route, theme control, or partial
// silently drift away from its documented status.
func TestBrandingInventory(t *testing.T) {
	raw, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Operations []struct {
			Method, Route, Scope, Request, Response, Disposition string
			Sources                                              []string
		}
		ThemeFields  []struct{ Name, RuntimeTarget, Disposition string }  `json:"theme_fields"`
		PartialSlots []struct{ Prompt, Screen, Slot, Disposition string } `json:"partial_slots"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"GET /api/v2/branding": false, "PATCH /api/v2/branding": false,
		"GET /api/v2/branding/templates/universal-login": false, "PUT /api/v2/branding/templates/universal-login": false, "DELETE /api/v2/branding/templates/universal-login": false,
		"POST /api/v2/branding/themes": false, "GET /api/v2/branding/themes/default": false,
		"GET /api/v2/branding/themes/{themeId}": false, "PATCH /api/v2/branding/themes/{themeId}": false, "DELETE /api/v2/branding/themes/{themeId}": false,
		"GET /api/v2/prompts": false, "PATCH /api/v2/prompts": false,
		"GET /api/v2/prompts/{prompt}/custom-text/{language}": false, "PUT /api/v2/prompts/{prompt}/custom-text/{language}": false,
		"GET /api/v2/prompts/{prompt}/partials": false, "PUT /api/v2/prompts/{prompt}/partials": false,
	}
	for _, o := range inv.Operations {
		key := o.Method + " " + o.Route
		if _, ok := wanted[key]; !ok {
			t.Errorf("unexpected operation %s", key)
			continue
		}
		if wanted[key] {
			t.Errorf("duplicate operation %s", key)
		}
		wanted[key] = true
		if o.Scope == "" || o.Request == "" || o.Response == "" || len(o.Sources) == 0 || o.Disposition == "" {
			t.Errorf("incomplete contract for %s", key)
		}
	}
	for key, ok := range wanted {
		if !ok {
			t.Errorf("missing operation %s", key)
		}
	}
	if len(inv.ThemeFields) < 25 {
		t.Errorf("theme fields: got %d, want >=25", len(inv.ThemeFields))
	}
	for _, f := range inv.ThemeFields {
		if f.Name == "" || f.Disposition == "" || (f.Disposition == "effective" && f.RuntimeTarget == "") {
			t.Errorf("theme field missing target or status: %+v", f)
		}
	}
	if len(inv.PartialSlots) < 16 {
		t.Errorf("partial slots: got %d, want >=16", len(inv.PartialSlots))
	}
	for _, s := range inv.PartialSlots {
		if s.Prompt == "" || s.Screen == "" || s.Slot == "" || s.Disposition == "" {
			t.Errorf("partial slot incomplete: %+v", s)
		}
	}
}
