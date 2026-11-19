package seed

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const githubSeed = `
tenants:
 - name: acme
   domains: [acme.test]
   connections:
    - name: github
      strategy: github
      options:
       client_id: Iv1.example
       client_secret: gh-throwaway-secret
       read_user: true
       repo_status: true
       OPTEXTRA
`

func TestSeedGitHub(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	f, err := Parse([]byte(strings.Replace(githubSeed, "OPTEXTRA", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.Connections().GetByName(ctx, tn.ID, "github")
	if err != nil {
		t.Fatal(err)
	}
	var scope []string
	switch v := c.Extra["scope"].(type) {
	case []string:
		scope = v
	case []any:
		for _, e := range v {
			scope = append(scope, e.(string))
		}
	}
	if got := strings.Join(scope, " "); got != "user:email read:user repo:status" {
		t.Fatalf("effective scope %q (%T)", got, c.Extra["scope"])
	}
	if c.Strategy != "github" {
		t.Fatalf("strategy %q", c.Strategy)
	}

	for _, extra := range []string{"authorizationURL: https://evil.example/authorize", "scope: [repo]"} {
		if _, err := Parse([]byte(strings.Replace(githubSeed, "OPTEXTRA", extra, 1))); err == nil {
			t.Fatalf("%q accepted", extra)
		}
	}
}
