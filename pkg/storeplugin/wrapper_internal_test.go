package storeplugin

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPluginWrapperExposesWebAuthnProbe(t *testing.T) {
	var s store.Store = &opened{}
	if _, ok := s.(store.WebAuthnSupporter); !ok {
		t.Fatal("SDK wrapper hides the webauthn.v1 probe")
	}
}
