package i18n

import (
	"fmt"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPromptTextMapping(t *testing.T) {
	tn := &store.Tenant{Name: "Acme", CustomText: store.CustomText{"login-id": {"fr": {"login-id": {"var-team": "Équipe ${companyName}"}}}}}
	text := New(tn, "fr").ScreenText("login-id", "login-id")
	if text["varTeam"] != "Équipe Acme" || text["title"] != "Sign in" {
		t.Fatalf("screen text=%v", text)
	}
}

func TestPromptCustomVariableLimit(t *testing.T) {
	keys := map[string]string{}
	ct := store.CustomText{"login-id": {"en": {"login-id": keys}}}
	for i := 0; i < 30; i++ {
		keys[fmt.Sprintf("var-custom%d", i)] = "Value"
	}
	if err := ValidateCustomText([]string{"en"}, ct); err != nil {
		t.Fatalf("30 variables rejected: %v", err)
	}
	keys["var-extra"] = "Value"
	if ValidateCustomText([]string{"en"}, ct) == nil {
		t.Fatal("31 variables accepted")
	}
}
