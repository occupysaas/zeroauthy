package signupactions

import (
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOrganizationSnapshot(t *testing.T) {
	org := &store.Organization{ID: "org_bound", Name: "acme", Metadata: map[string]string{"tier": "gold"}}
	in := WithOrganization(actions.RegistrationInput{}, org)
	org.Name = "changed"
	org.Metadata["tier"] = "silver"
	if in.Organization.Name != "acme" || in.Organization.Metadata["tier"] != "gold" {
		t.Fatal("registration context shares mutable organization")
	}
}
