package brandingrules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOrganizationTemplates(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t"}
	next, err := Merge(c, "text:organizations:en", []byte(`{"organization-selection":{"title":"Custom selection"},"organization-picker":{"title":"Custom picker"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, screen := range []string{"login", "pre-login-organization-picker", "unknown"} {
		if _, err := Merge(next, "text:organizations:en", []byte(`{"`+screen+`":{"title":"Wrong"}}`)); err == nil {
			t.Errorf("accepted unrelated screen %s", screen)
		}
	}
}
