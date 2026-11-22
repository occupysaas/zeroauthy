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

func TestPluginWrapperExposesClientCredentialsProbe(t *testing.T) {
	var s store.Store = &opened{}
	if _, ok := s.(store.ClientCredentialsSupporter); !ok {
		t.Fatal("SDK wrapper hides the client_credentials.v1 probe")
	}
}

func TestPluginWrapperExposesRefreshIIProbe(t *testing.T) {
	var wrapper store.Store = &opened{}
	if _, ok := wrapper.(store.RefreshTokensIISupporter); !ok {
		t.Fatal("SDK wrapper hides the refresh_tokens_ii.v1 probe")
	}
}

func TestPluginWrapperExposesOIDCLogout(t *testing.T) {
	var wrapper store.Store = &opened{}
	if _, ok := wrapper.(store.OIDCLogoutSupporter); !ok {
		t.Fatal("SDK wrapper hides oidc_logout.v1 probe")
	}
	if _, ok := wrapper.(store.GlobalRevocationStore); !ok {
		t.Fatal("SDK wrapper hides global revocation state")
	}
}
