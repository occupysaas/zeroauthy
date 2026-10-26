package mgmt_test

import (
	"net/http"
	"testing"

	"strings"
)

func TestBrandingManagementContract(t *testing.T) {
	e := newClientsEnv(t)
	patch, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PATCH", "/api/v2/branding", map[string]any{"colors": map[string]any{"primary": "#112233"}, "logo_url": "https://example.test/logo.svg"}, e.h.UpdateBranding)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch=%d body=%s", patch.Code, patch.Body.String())
	}
	get, _ := e.call(t, e.tn, m2mCaller("read:branding"), "GET", "/api/v2/branding", nil, e.h.GetBranding)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "#112233") {
		t.Fatalf("get=%d body=%s", get.Code, get.Body.String())
	}
	bad, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PATCH", "/api/v2/branding", map[string]any{"colors": map[string]any{"primary": nil}}, e.h.UpdateBranding)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("null color=%d", bad.Code)
	}
	badColors, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PATCH", "/api/v2/branding", map[string]any{"colors": nil}, e.h.UpdateBranding)
	if badColors.Code != http.StatusBadRequest {
		t.Fatalf("null colors object=%d", badColors.Code)
	}
	foreign, _ := e.call(t, e.sys, m2mCaller("update:branding"), "PATCH", "/api/v2/branding", map[string]any{"logo_url": "https://example.test/x.svg"}, e.h.UpdateBranding)
	if foreign.Code == http.StatusOK {
		t.Fatal("reserved tenant was writable")
	}
}
