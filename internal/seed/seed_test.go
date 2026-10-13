package seed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const sample = `
tenants:
  - name: acme
    friendly_name: Acme
    domains: ["Login.Acme.TEST", "localhost:8443"]
    default_audience: https://api.acme.test
    resource_servers:
      - identifier: https://api.acme.test
        name: Acme API
        token_lifetime: 3600
        scopes:
          - {value: "read:things", description: "Read things"}
          - {value: "write:things", description: "Write things"}
    clients:
      - client_id: m2m
        name: Backend
        app_type: non_interactive
        client_secret: first-secret
        grant_types: [client_credentials]
      - client_id: spa
        name: Web
        app_type: spa
        callbacks: ["https://app.acme.test/callback"]
    client_grants:
      - client_id: m2m
        audience: https://api.acme.test
        scopes: ["read:things"]
`

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }

func TestApply(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}

	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tn.Domains, ",") != "login.acme.test,localhost:8443" {
		t.Errorf("domains not normalized: %v", tn.Domains)
	}
	if tn.DefaultAudience != "https://api.acme.test" || !strings.HasPrefix(tn.ID, "ten_") {
		t.Errorf("tenant = %+v", tn)
	}

	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test")
	if err != nil || rs.TokenLifetime != 3600 || len(rs.Scopes) != 2 || rs.SigningAlg != "RS256" {
		t.Fatalf("resource server = %+v, %v", rs, err)
	}

	m2m, err := st.Clients().Get(ctx, tn.ID, "m2m")
	if err != nil {
		t.Fatal(err)
	}
	if m2m.TokenEndpointAuthMethod != store.AuthMethodClientSecretPost {
		t.Errorf("default auth method for non_interactive = %q", m2m.TokenEndpointAuthMethod)
	}
	if len(m2m.Secrets) != 1 {
		t.Fatalf("secrets = %d", len(m2m.Secrets))
	}
	if ok, _ := secrets.Verify(m2m.Secrets[0].Hash, "first-secret"); !ok {
		t.Error("stored hash does not verify against seed secret")
	}

	spa, _ := st.Clients().Get(ctx, tn.ID, "spa")
	if spa.TokenEndpointAuthMethod != store.AuthMethodNone || len(spa.Secrets) != 0 {
		t.Errorf("spa = %+v", spa)
	}

	g, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test")
	if err != nil || strings.Join(g.Scopes, " ") != "read:things" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte(sample))
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn1, _ := st.Tenants().GetByName(ctx, "acme")
	c1, _ := st.Clients().Get(ctx, tn1.ID, "m2m")
	rs1, _ := st.ResourceServers().GetByIdentifier(ctx, tn1.ID, "https://api.acme.test")

	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn2, _ := st.Tenants().GetByName(ctx, "acme")
	c2, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	rs2, _ := st.ResourceServers().GetByIdentifier(ctx, tn2.ID, "https://api.acme.test")
	if tn1.ID != tn2.ID || rs1.ID != rs2.ID || c1.Secrets[0].Hash != c2.Secrets[0].Hash {
		t.Fatal("second Apply changed IDs or re-hashed an unchanged secret")
	}

	changed, _ := Parse([]byte(strings.Replace(sample, "first-secret", "second-secret", 1)))
	if err := Apply(ctx, st, changed, fixedNow); err != nil {
		t.Fatal(err)
	}
	c3, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	if ok, _ := secrets.Verify(c3.Secrets[0].Hash, "second-secret"); !ok || len(c3.Secrets) != 1 {
		t.Fatal("changed secret was not applied")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown field":         {`tenants: [{name: a, domainz: [x]}]`, "domainz"},
		"no name":               {`tenants: [{domains: [x]}]`, "name is required"},
		"dup tenant":            {`tenants: [{name: a}, {name: a}]`, `duplicate tenant "a"`},
		"bad app type":          {`tenants: [{name: a, clients: [{client_id: c, app_type: robot}]}]`, `app_type "robot"`},
		"secret missing":        {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive}]}]`, "client_secret is required"},
		"secret on public":      {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, client_secret: x}]}]`, "must not have a client_secret"},
		"grant unknown client":  {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], client_grants: [{client_id: nope, audience: "https://x"}]}]`, `unknown client "nope"`},
		"grant unknown api":     {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://nope"}]}]`, `unknown audience "https://nope"`},
		"grant undefined scope": {`tenants: [{name: a, resource_servers: [{identifier: "https://x", scopes: [{value: r}]}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", scopes: [w]}]}]`, `scope "w"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
