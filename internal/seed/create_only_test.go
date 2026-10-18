package seed

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const createOnlySeed = `
tenants:
  - name: acme
    friendly_name: Acme
    domains: [acme.test]
    default_directory: Db
    resource_servers:
      - {identifier: "https://api.acme.test", name: Acme API, scopes: [{value: "read:things"}, {value: "write:things"}]}
    clients:
      - {client_id: m2m, name: Backend, app_type: non_interactive, client_secret: first-secret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: "https://api.acme.test", scopes: ["read:things"]}
    connections:
      - {name: Db, enabled_clients: [m2m], password_policy: {min_length: 10}}
    users:
      - {connection: Db, email: alice@acme.test, password: "alice password 1", name: Alice}
`

// The same tenant, every entity different, and one more of each.
const createOnlySeedMore = `
tenants:
  - name: acme
    friendly_name: Acme Again
    domains: [acme.test]
    default_directory: Db
    resource_servers:
      - {identifier: "https://api.acme.test", name: Seed Name, scopes: [{value: "read:things"}]}
      - {identifier: "https://two.acme.test", name: Two, scopes: [{value: "read:two"}]}
    clients:
      - {client_id: m2m, name: Seed Backend, app_type: non_interactive, client_secret: other-secret, grant_types: [client_credentials]}
      - {client_id: m2m2, name: Backend 2, app_type: non_interactive, client_secret: second-secret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: "https://api.acme.test", scopes: ["read:things"]}
      - {client_id: m2m2, audience: "https://two.acme.test", scopes: ["read:two"]}
    connections:
      - {name: Db, enabled_clients: [m2m], password_policy: {min_length: 12}}
      - {name: Db2, enabled_clients: [m2m2]}
    users:
      - {connection: Db, email: alice@acme.test, password: "another password 2", name: Seed Alice}
      - {connection: Db, email: bob@acme.test, password: "bob password 1", name: Bob}
`

func TestCreateOnlyMode(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	apply := func(doc string, mode Mode) {
		t.Helper()
		f, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		f.Mode = mode
		if err := Apply(ctx, st, f, fixedNow, w); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	apply(createOnlySeed, ModeCreateOnly)
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil || tn.Seeded {
		t.Fatalf("tenant = %+v, %v; a create-only tenant is not marked seeded", tn, err)
	}

	// Console edits.
	tn.FriendlyName = "Edited"
	must(st.Tenants().Update(ctx, tn))
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test")
	must(err)
	rs.Name = "Edited API"
	must(st.ResourceServers().Update(ctx, rs))
	c, err := st.Clients().Get(ctx, tn.ID, "m2m")
	must(err)
	c.Name = "Edited Backend"
	must(st.Clients().Update(ctx, c))
	sealed := slices.Clone(c.Secrets)
	g, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test", store.SubjectTypeClient)
	must(err)
	g.Scopes = []string{"read:things", "write:things"}
	must(st.ClientGrants().Update(ctx, g))
	conn, err := st.Connections().GetByName(ctx, tn.ID, "Db")
	must(err)
	conn.PasswordOptions.Complexity.MinLength = 8
	must(st.Connections().Update(ctx, conn))
	u, err := st.Users().FindByLogin(ctx, tn.ID, "Db", "alice@acme.test")
	must(err)
	u.Name = "Edited Alice"
	must(st.Users().Update(ctx, u))

	// Applying a seed that differs in every entity changes none of them.
	apply(createOnlySeedMore, ModeCreateOnly)
	if got, _ := st.Tenants().GetByName(ctx, "acme"); got.FriendlyName != "Edited" {
		t.Errorf("tenant friendly name = %q", got.FriendlyName)
	}
	if got, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test"); got.Name != "Edited API" || len(got.Scopes) != 2 {
		t.Errorf("resource server = %+v", got)
	}
	if got, _ := st.Clients().Get(ctx, tn.ID, "m2m"); got.Name != "Edited Backend" ||
		!slices.EqualFunc(got.Secrets, sealed, func(a, b store.ClientSecret) bool { return bytes.Equal(a.Sealed, b.Sealed) }) {
		t.Errorf("client = %+v", got)
	}
	if got, _ := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test", store.SubjectTypeClient); !slices.Equal(got.Scopes, []string{"read:things", "write:things"}) {
		t.Errorf("client grant scopes = %v", got.Scopes)
	}
	if got, _ := st.Connections().GetByName(ctx, tn.ID, "Db"); got.PasswordOptions.Complexity.MinLength != 8 {
		t.Errorf("connection = %+v", got)
	}
	if got, _ := st.Users().FindByLogin(ctx, tn.ID, "Db", "alice@acme.test"); got.Name != "Edited Alice" {
		t.Errorf("user = %+v", got)
	}
	// What is new is created.
	if _, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://two.acme.test"); err != nil {
		t.Errorf("new resource server: %v", err)
	}
	if _, err := st.Clients().Get(ctx, tn.ID, "m2m2"); err != nil {
		t.Errorf("new client: %v", err)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "m2m2", "https://two.acme.test", store.SubjectTypeClient); err != nil {
		t.Errorf("new client grant: %v", err)
	}
	if _, err := st.Connections().GetByName(ctx, tn.ID, "Db2"); err != nil {
		t.Errorf("new connection: %v", err)
	}
	if _, err := st.Users().FindByLogin(ctx, tn.ID, "Db", "bob@acme.test"); err != nil {
		t.Errorf("new user: %v", err)
	}

	// The default mode still overwrites, and marks the tenant seeded.
	apply(createOnlySeedMore, ModeApply)
	if got, _ := st.Tenants().GetByName(ctx, "acme"); got.FriendlyName != "Acme Again" || !got.Seeded {
		t.Errorf("apply mode left tenant %+v", got)
	}
	if got, _ := st.Clients().Get(ctx, tn.ID, "m2m"); got.Name != "Seed Backend" {
		t.Errorf("apply mode left client %q", got.Name)
	}
	// Switching back to create-only clears the marker on a seeded tenant.
	apply(createOnlySeedMore, ModeCreateOnly)
	if got, _ := st.Tenants().GetByName(ctx, "acme"); got.Seeded {
		t.Error("create-only left the seeded marker on")
	}
}
