package seed

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const myAccountSeed = `
tenants:
  - name: acme
    domains: [login.acme.test]
    my_account_api: {active: ACTIVE}
    clients:
      - {client_id: app, app_type: spa, callbacks: ["https://app.acme.test/cb"]}
    client_grants:
      - {client_id: app, audience: "AUD", subject_type: SUBJECT, scopes: ["read:me:authentication_methods", "read:me:factors"]}
`

func myAccountFile(active, aud, subject string) string {
	return strings.NewReplacer("ACTIVE", active, "AUD", aud, "SUBJECT", subject).Replace(myAccountSeed)
}

// LR42a-7: my_account_api.active creates the My Account API; user client
// grants may name it.
func TestSeedMyAccountAPI(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(myAccountFile("true", "https://login.acme.test/me/", "user")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://login.acme.test/me/")
	if err != nil || !rs.IsSystem || rs.Name != tenantsetup.MyAccountAPIName || rs.SubjectTypeAuthorization.User != store.PolicyRequireClientGrant {
		t.Fatalf("API = %+v %v", rs, err)
	}
	g, err := st.ClientGrants().Find(ctx, tn.ID, "app", rs.Identifier, store.SubjectTypeUser)
	if err != nil || !slices.Equal(g.Scopes, []string{"read:me:authentication_methods", "read:me:factors"}) {
		t.Fatalf("grant = %+v %v", g, err)
	}
	// Applying again is a no-op; active: false deactivates.
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	off, _ := Parse([]byte(strings.Replace(myAccountFile("false", "https://login.acme.test/me/", "user"), "    client_grants:\n      - {client_id: app, audience: \"https://login.acme.test/me/\", subject_type: user, scopes: [\"read:me:authentication_methods\", \"read:me:factors\"]}\n", "", 1)))
	if err := Apply(ctx, st, off, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://login.acme.test/me/"); err != store.ErrNotFound {
		t.Fatalf("after active: false: %v", err)
	}
}

func TestSeedMyAccountAPIRefusals(t *testing.T) {
	for name, text := range map[string]string{
		"inactive":      myAccountFile("false", "https://login.acme.test/me/", "user"),
		"client grant":  myAccountFile("true", "https://login.acme.test/me/", "client"),
		"other host":    myAccountFile("true", "https://other.test/me/", "user"),
		"unknown scope": strings.Replace(myAccountFile("true", "https://login.acme.test/me/", "user"), `"read:me:factors"`, `"read:me:profile"`, 1),
	} {
		f, err := Parse([]byte(text))
		if err == nil {
			err = Apply(context.Background(), memory.New(), f, fixedNow, testWrapper(t))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
