package hostedlogin

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestLocalizedTenant(t *testing.T) {
	legacy := &store.Tenant{ID: "t", CustomText: store.CustomText{"login": {"en": {"login": {"title": "old"}}}}}
	c := &store.HostedLoginConfig{CustomText: store.CustomText{"login": {"en": {"login": {"title": "new"}}}}}
	view := LocalizedTenant(legacy, c)
	if view.CustomText["login"]["en"]["login"]["title"] != "new" {
		t.Fatal("canonical text missing")
	}
	view.CustomText["login"]["en"]["login"]["title"] = "changed"
	if legacy.CustomText["login"]["en"]["login"]["title"] != "old" || c.CustomText["login"]["en"]["login"]["title"] != "new" {
		t.Fatal("shared text mutated")
	}
	if fallback := LocalizedTenant(legacy, nil); fallback.CustomText["login"]["en"]["login"]["title"] != "old" {
		t.Fatal("legacy fallback lost")
	}
}
