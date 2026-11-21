package oauth

import (
	"strings"
	"testing"
)

func TestPhoneAddressScopesSurviveTokenExchange(t *testing.T) {
	got := userScopes([]string{"openid", "phone", "address"}, nil, false)
	if strings.Join(got, " ") != "openid phone address" {
		t.Fatalf("granted OIDC scopes lost at exchange: %v", got)
	}
}
