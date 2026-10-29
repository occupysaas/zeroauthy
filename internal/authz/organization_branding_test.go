package authz

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A protected callback renders the same bound organization as hosted login.
func TestOrganizationBrandingError(t *testing.T) {
	e := newEnv(t)
	logo := "https://org-assets.test/logo.svg"
	org := &store.Organization{TenantID: e.tenant.ID, ID: "org_0000000000000001", Name: "acme", DisplayName: "Acme", Branding: &store.OrgBranding{LogoURL: &logo, Colors: &store.OrgColors{Primary: "#abcdef", PageBackground: "#fedcba"}}}
	if err := e.st.Organizations().Create(context.Background(), org, nil); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.h.deny(rec, httptest.NewRequest("GET", "https://acme.example.test/authorize", nil), e.res(), &store.Client{IsFirstParty: false}, Request{OrgID: org.ID}, errInvalidRequest("test"))
	if !strings.Contains(rec.Body.String(), logo) || !strings.Contains(rec.Body.String(), "#abcdef") {
		t.Fatal("protected authorization error lost organization branding")
	}
}
