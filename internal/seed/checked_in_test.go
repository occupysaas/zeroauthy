package seed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestCheckedInSeeds loads and applies the seed files the test harnesses use
// (tests/*/seed.yaml), so a schema change cannot break them unnoticed.
func TestCheckedInSeeds(t *testing.T) {
	paths, err := filepath.Glob("../../tests/*/seed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no tests/*/seed.yaml found")
	}
	for _, p := range paths {
		t.Run(filepath.Base(filepath.Dir(p)), func(t *testing.T) {
			f, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			// As serve does; the test harnesses run without a base domain.
			if err := f.CheckManagementAPI(""); err != nil {
				t.Fatal(err)
			}
			if err := Apply(context.Background(), memory.New(), f, fixedNow, testWrapper(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPublicSeedTemplate renders the hosted certification seed
// (tests/conformance/public/seed.yaml.tmpl) the way make-seed.sh does and
// applies it, so the template keeps passing seed validation.
func TestPublicSeedTemplate(t *testing.T) {
	tmpl, err := os.ReadFile("../../tests/conformance/public/seed.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	rendered := strings.NewReplacer(
		"@@HOST@@", "auth.example.com",
		"@@ALIAS@@", "zeroauthy",
		"@@CLIENT1_SECRET@@", strings.Repeat("a1", 32),
		"@@CLIENT2_SECRET@@", strings.Repeat("b2", 32),
		"@@CLIENT_POST_SECRET@@", strings.Repeat("c3", 32),
		"@@USER_PASSWORD@@", "Za-0123456789abcdef01234567",
	).Replace(string(tmpl))
	if strings.Contains(rendered, "@@") {
		t.Fatal("unreplaced placeholder in the rendered seed")
	}
	f, err := Parse([]byte(rendered))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := memory.New()
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "certification")
	if err != nil {
		t.Fatal(err)
	}
	if len(tn.Domains) != 1 || tn.Domains[0] != "auth.example.com" {
		t.Errorf("domains = %v", tn.Domains)
	}
	for _, id := range []string{"za-cert-1", "za-cert-2", "za-cert-post"} {
		c, err := st.Clients().Get(ctx, tn.ID, id)
		if err != nil {
			t.Fatalf("client %s: %v", id, err)
		}
		if len(c.Callbacks) != 1 || c.Callbacks[0] != "https://www.certification.openid.net/test/a/zeroauthy/callback" {
			t.Errorf("client %s callbacks = %v", id, c.Callbacks)
		}
	}
	u, err := st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "conformance@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name == "" || u.GivenName == "" || u.FamilyName == "" || !u.EmailVerified {
		t.Errorf("user = %+v", u)
	}
}
