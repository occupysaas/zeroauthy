package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise policy through the authenticated token endpoint, not a helper-only path.
func TestOrganizationM2MPolicyMatrix(t *testing.T) {
	for _, usage := range []string{"", "deny", "allow", "require"} {
		for _, withOrg := range []bool{false, true} {
			for _, association := range []string{"none", "explicit", "any"} {
				t.Run(fmt.Sprintf("%s/org=%v/%s", usage, withOrg, association), func(t *testing.T) {
					f := newFixture(t)
					ctx := context.Background()
					tid := f.tenantID(t, "acme")
					o := &store.Organization{TenantID: tid, ID: "org_0000000000000001", Name: "machine", DisplayName: "Machine", IsAppEntitlementActive: true}
					if err := f.st.Organizations().Create(ctx, o, nil); err != nil {
						t.Fatal(err)
					}
					g, err := f.st.ClientGrants().Find(ctx, tid, "m2m", "https://api.acme.test", store.SubjectTypeClient)
					if err != nil {
						t.Fatal(err)
					}
					g.OrganizationUsage = usage
					g.AllowAnyOrganization = association == "any"
					if err := f.st.ClientGrants().Update(ctx, g); err != nil {
						t.Fatal(err)
					}
					if association == "explicit" {
						if err := f.st.OrganizationsII().PutClientGrant(ctx, tid, o.ID, g.ID); err != nil {
							t.Fatal(err)
						}
					}
					form := cc("m2m", "m2m-secret")
					if withOrg {
						form.Set("organization", o.ID)
					}
					rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
					want := (!withOrg && usage != "require") || (withOrg && (usage == "allow" || usage == "require") && association != "none")
					if !want {
						if rec.Code != 403 || body["error"] != "access_denied" {
							t.Fatalf("want access_denied, %d %v", rec.Code, body)
						}
						return
					}
					if rec.Code != 200 {
						t.Fatalf("want success, %d %v", rec.Code, body)
					}
					claims, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
					if withOrg && claims["org_id"] != o.ID {
						t.Fatalf("claims %v", claims)
					}
					if !withOrg && claims["org_id"] != nil {
						t.Fatalf("inferred organization %v", claims)
					}
					if claims["org_name"] != nil || body["id_token"] != nil || body["refresh_token"] != nil {
						t.Fatalf("unexpected tokens/claims %v %v", body, claims)
					}
					members, err := f.st.Organizations().Members(ctx, tid, o.ID, store.OrgPage{PerPage: 100})
					if err != nil || len(members.Items) != 0 {
						t.Fatalf("membership mutation %v %v", members, err)
					}
				})
			}
		}
	}
}

func TestOrganizationM2MExplicitContext(t *testing.T) {
	for _, tc := range []struct {
		name, raw                          string
		names, third, any, optin, explicit bool
		status                             int
		code                               string
	}{
		{name: "id", raw: "org_0000000000000001", explicit: true, status: 200},
		{name: "name on", raw: "machine", names: true, explicit: true, status: 200},
		{name: "name off", raw: "machine", explicit: true, status: 400, code: "invalid_request"},
		{name: "missing", raw: "org_0000000000000002", any: true, status: 403, code: "access_denied"},
		{name: "third any", raw: "org_0000000000000001", third: true, any: true, optin: true, explicit: true, status: 403, code: "access_denied"},
		{name: "third no optin", raw: "org_0000000000000001", third: true, explicit: true, status: 403, code: "access_denied"},
		{name: "third explicit", raw: "org_0000000000000001", third: true, optin: true, explicit: true, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			tn, err := f.st.Tenants().Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			if tn.SettingsExtra == nil {
				tn.SettingsExtra = map[string]any{}
			}
			tn.SettingsExtra["allow_organization_name_in_authentication_api"] = tc.names
			if err := f.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			o := &store.Organization{TenantID: tid, ID: "org_0000000000000001", Name: "machine", DisplayName: "Machine", IsAppEntitlementActive: true}
			if tc.optin {
				o.ThirdPartyClientAccess = "allow"
			}
			if err := f.st.Organizations().Create(ctx, o, nil); err != nil {
				t.Fatal(err)
			}
			c, err := f.st.Clients().Get(ctx, tid, "m2m")
			if err != nil {
				t.Fatal(err)
			}
			c.IsFirstParty = !tc.third
			c.OrganizationUsage = "deny"
			if err := f.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			g, err := f.st.ClientGrants().Find(ctx, tid, "m2m", "https://api.acme.test", store.SubjectTypeClient)
			if err != nil {
				t.Fatal(err)
			}
			g.OrganizationUsage = "allow"
			g.AllowAnyOrganization = tc.any
			g.Scopes = []string{"read:things"}
			if err := f.st.ClientGrants().Update(ctx, g); err != nil {
				t.Fatal(err)
			}
			if tc.explicit {
				if err := f.st.OrganizationsII().PutClientGrant(ctx, tid, o.ID, g.ID); err != nil {
					t.Fatal(err)
				}
			}
			rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "organization", tc.raw)})
			if rec.Code != tc.status || (tc.code != "" && body["error"] != tc.code) {
				t.Fatalf("%d %v", rec.Code, body)
			}
			if rec.Code == 200 {
				claims, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
				if claims["org_id"] != o.ID || claims["scope"] != "read:things" {
					t.Fatal(claims)
				}
				if tc.names && claims["org_name"] != "machine" {
					t.Fatal(claims)
				}
				if !tc.names && claims["org_name"] != nil {
					t.Fatal(claims)
				}
			}
		})
	}
}

func TestOrganizationM2MActionSnapshot(t *testing.T) {
	f := newActionsFixture(t)
	ctx := context.Background()
	o := &store.Organization{TenantID: f.tid, ID: "org_0000000000000001", Name: "machine", DisplayName: "Machine", Metadata: map[string]string{"frozen": "yes"}}
	if err := f.st.Organizations().Create(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	g, err := f.st.ClientGrants().Find(ctx, f.tid, "m2m", acmeAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	g.OrganizationUsage = "allow"
	g.AllowAnyOrganization = true
	g.Scopes = []string{"read:things"}
	if err := f.st.ClientGrants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	tn, err := f.st.Tenants().Get(ctx, f.tid)
	if err != nil {
		t.Fatal(err)
	}
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["allow_organization_name_in_authentication_api"] = true
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current, err := f.st.Organizations().Get(r.Context(), f.tid, o.ID)
		if err != nil {
			http.Error(w, "read", 500)
			return
		}
		current.Name = "changed"
		current.Metadata = map[string]string{"frozen": "no"}
		if err := f.st.Organizations().Update(r.Context(), current); err != nil {
			http.Error(w, "write", 500)
			return
		}
		w.WriteHeader(204)
	}))
	defer relay.Close()
	first := f.actions.Deploy(t, f.tid, actions.TriggerCredentialsExchange, "snapshot", fmt.Sprintf(`exports.onExecuteCredentialsExchange=async(event,api)=>{
 if(event.organization.id!=="org_0000000000000001" || event.organization.name!=="machine" || event.organization.metadata.frozen!=="yes") {api.access.deny("invalid_request","missing snapshot");return;}
 const r=await fetch(%q);if(!r.ok)throw Error("update");
 event.organization.id="org_forged";
 api.accessToken.setCustomClaim("org_id","org_forged"); api.accessToken.setCustomClaim("org_name","forged");
 api.transaction.addTargetScope("write:things"); api.transaction.addTargetScope("delete:everything");
 api.accessToken.setCustomClaim("https://test/snapshot","present");
 };`, relay.URL))
	second := f.actions.Deploy(t, f.tid, actions.TriggerCredentialsExchange, "second snapshot", `exports.onExecuteCredentialsExchange=async(event,api)=>{if(event.organization.id!=="org_0000000000000001"||event.organization.name!=="machine"||event.organization.metadata.frozen!=="yes")throw Error("snapshot changed");};`)
	f.actions.Bind(t, f.tid, actions.TriggerCredentialsExchange, first, second)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "organization", o.ID)})
	if rec.Code != 200 {
		t.Fatalf("%d %v", rec.Code, body)
	}
	claims, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if claims["org_id"] != o.ID || claims["org_name"] != "machine" || claims["scope"] != "read:things" || claims["https://test/snapshot"] != "present" {
		t.Fatal(claims)
	}
}

// Pause immediately before the final transaction, letting a policy writer
// commit first. There are no sleeps: channels define the winner deterministically.
type machineMintBarrier struct {
	store.Store
	reached, resume chan struct{}
}

func (b machineMintBarrier) WithTx(ctx context.Context, fn func(store.Store) error) error {
	close(b.reached)
	select {
	case <-b.resume:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.Store.WithTx(ctx, fn)
}

func TestOrganizationM2MRevocationRace(t *testing.T) {
	for dialect, mk := range machineSQLDatabases(t) {
		t.Run(dialect, func(t *testing.T) {
			for _, kind := range []string{"association", "grant-delete", "grant-policy", "organization-delete", "third-party-optout", "grant-scopes", "api-scopes"} {
				t.Run(kind, func(t *testing.T) {
					f := newFixture(t)
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					sqlst, err := sqlstore.Open(ctx, mk(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sqlst.Close()
					must := func(err error) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
					}
					must(sqlst.Migrate(ctx))
					seedFile, err := seed.Parse([]byte(fixtureSeed))
					must(err)
					must(seed.Apply(ctx, sqlst, seedFile, fixedNow, f.wrapper))
					f.st = sqlst
					f.h.Store = sqlst
					tid := f.tenantID(t, "acme")
					must(f.keys.Ensure(ctx, tid))
					o := &store.Organization{TenantID: tid, ID: "org_0000000000000001", Name: "machine", DisplayName: "Machine", ThirdPartyClientAccess: "allow"}
					must(sqlst.Organizations().Create(ctx, o, nil))
					g, err := sqlst.ClientGrants().Find(ctx, tid, "m2m", acmeAPI, store.SubjectTypeClient)
					must(err)
					g.OrganizationUsage = "allow"
					must(sqlst.ClientGrants().Update(ctx, g))
					must(sqlst.OrganizationsII().PutClientGrant(ctx, tid, o.ID, g.ID))
					if kind == "third-party-optout" {
						c, err := sqlst.Clients().Get(ctx, tid, "m2m")
						must(err)
						c.IsFirstParty = false
						must(sqlst.Clients().Update(ctx, c))
					}
					reached, resume := make(chan struct{}), make(chan struct{})
					f.h.Store = machineMintBarrier{sqlst, reached, resume}
					handler := f.server(t, true)
					req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(cc("m2m", "m2m-secret", "organization", o.ID).Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					rec := httptest.NewRecorder()
					done := make(chan struct{})
					go func() { defer close(done); handler.ServeHTTP(rec, req) }()
					select {
					case <-reached:
					case <-ctx.Done():
						t.Fatal("mint transaction never reached")
					}
					switch kind {
					case "association":
						must(sqlst.OrganizationsII().DeleteClientGrant(ctx, tid, o.ID, g.ID))
					case "grant-delete":
						must(sqlst.ClientGrants().Delete(ctx, tid, g.ID))
					case "grant-policy":
						g.OrganizationUsage = "deny"
						must(sqlst.ClientGrants().Update(ctx, g))
					case "organization-delete":
						must(sqlst.Organizations().Delete(ctx, tid, o.ID))
					case "third-party-optout":
						o.ThirdPartyClientAccess = "block"
						must(sqlst.Organizations().Update(ctx, o))
					case "grant-scopes":
						g.Scopes = []string{"read:things"}
						must(sqlst.ClientGrants().Update(ctx, g))
					case "api-scopes":
						api, err := sqlst.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
						must(err)
						api.Scopes = []store.Scope{{Value: "read:things"}}
						must(sqlst.ResourceServers().Update(ctx, api))
					}
					close(resume)
					select {
					case <-done:
					case <-ctx.Done():
						t.Fatal("mint did not finish")
					}
					var body map[string]any
					must(json.Unmarshal(rec.Body.Bytes(), &body))
					if kind == "grant-scopes" || kind == "api-scopes" {
						if rec.Code != 200 || body["scope"] != "read:things" {
							t.Fatalf("ceiling %d %v", rec.Code, body)
						}
					} else if rec.Code != 403 || body["error"] != "access_denied" || body["access_token"] != nil {
						t.Fatalf("revocation %d %v", rec.Code, body)
					}
				})
			}
		})
	}
}

// Each configured server dialect gets a fresh database for every race case.
func machineSQLDatabases(t *testing.T) map[string]func(*testing.T) string {
	out := map[string]func(*testing.T) string{"sqlite": func(t *testing.T) string { return "sqlite://" + filepath.Join(t.TempDir(), "machine.db") }}
	for kind, env := range map[string]string{"postgres": "ZA_TEST_POSTGRES_DSN", "mysql": "ZA_TEST_MYSQL_DSN"} {
		raw := os.Getenv(env)
		if raw == "" {
			continue
		}
		out[kind] = func(t *testing.T) string {
			t.Helper()
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			driver, native := "pgx", raw
			if kind == "mysql" {
				driver = "mysql"
				cfg := mysql.NewConfig()
				cfg.User = u.User.Username()
				cfg.Passwd, _ = u.User.Password()
				cfg.Net = "tcp"
				cfg.Addr = u.Host
				native = cfg.FormatDSN()
			}
			admin, err := sql.Open(driver, native)
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("z_m2m_%d", time.Now().UnixNano())
			if _, err := admin.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
				admin.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				defer admin.Close()
				drop := "DROP DATABASE IF EXISTS " + name
				if kind == "postgres" {
					drop += " WITH (FORCE)"
				}
				if _, err := admin.ExecContext(context.Background(), drop); err != nil {
					t.Error(err)
				}
			})
			u.Path = "/" + name
			return u.String()
		}
	}
	return out
}

func TestOrganizationM2MParameters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	other := &store.Organization{TenantID: f.tenantID(t, "globex"), ID: "org_0000000000000001", Name: "other", DisplayName: "Other"}
	if err := f.st.Organizations().Create(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	g, err := f.st.ClientGrants().Find(ctx, tid, "m2m", acmeAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	g.OrganizationUsage = "allow"
	g.AllowAnyOrganization = true
	if err := f.st.ClientGrants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	form := cc("m2m", "m2m-secret", "organization", other.ID)
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 403 || body["error"] != "access_denied" {
		t.Fatalf("tenant isolation %d %v", rec.Code, body)
	}
	form["organization"] = []string{other.ID, other.ID}
	if rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); rec.Code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("duplicate %d %v", rec.Code, body)
	}
	if rec, body := f.call(t, false, tokenCall{host: "acme.example.test", json: `{"grant_type":"client_credentials","client_id":"m2m","client_secret":"m2m-secret","organization":null}`}); rec.Code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("null %d %v", rec.Code, body)
	}
	form = cc("m2m", "m2m-secret", "organization", "")
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
		t.Fatalf("empty allow %d %v", rec.Code, body)
	}
	g.OrganizationUsage = "require"
	if err := f.st.ClientGrants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 403 || body["error"] != "access_denied" {
		t.Fatalf("empty require %d %v", rec.Code, body)
	}
}
