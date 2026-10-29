package hostedlogin

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestOrganizationBranding(t *testing.T) {
	cfg := &store.HostedLoginConfig{Branding: map[string]any{"logo_url": "https://tenant.test/logo.svg", "colors": map[string]any{"primary": "#112233"}}}
	base, err := ResolveTheme(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := ResolveTheme(cfg, nil)
	if err != nil || !reflect.DeepEqual(base, unchanged) {
		t.Fatalf("nil override changed theme: %+v %v", unchanged, err)
	}
	for _, org := range []*OrgView{{LogoURL: "javascript:alert(1)"}, {LogoURL: `https://org.test/logo.svg" onerror="alert(1)`}, {Primary: "red;display:none"}, {PageBackground: "url(https://evil.test)"}} {
		if _, err := ResolveTheme(cfg, org); err == nil {
			t.Errorf("unsafe organization branding accepted: %+v", org)
		}
	}
	// Resolving an overlay never mutates the tenant's shared configuration.
	_, err = ResolveTheme(cfg, &OrgView{Primary: "#abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := ResolveTheme(cfg)
	if err != nil || !reflect.DeepEqual(base, after) {
		t.Fatal("tenant theme mutated")
	}
}

func TestOrganizationTemplates(t *testing.T) {
	c := NewContext(&store.Organization{ID: "org_bound", Name: "acme", DisplayName: "Acme <Org>", Metadata: map[string]string{"tier": "<gold>"}})
	vars := c.Variables()
	vars["organization"].(map[string]any)["members"] = "private"
	out, err := RenderPartials(context.Background(), map[string]string{"form-footer-end": `<p>{{organization.id}} {{organization.display_name}} {{organization.metadata.tier}} [{{organization.members}}]</p>`}, vars, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Slots["form-footer-end"], "org_bound Acme &lt;Org&gt; &lt;gold&gt; []") {
		t.Fatalf("partial projection=%+v", out)
	}
}
