package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

type orgQueryCounter struct {
	querier
	queries []string
}

func (c *orgQueryCounter) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	c.queries = append(c.queries, q)
	return c.querier.QueryContext(ctx, q, args...)
}
func (c *orgQueryCounter) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	c.queries = append(c.queries, q)
	return c.querier.QueryRowContext(ctx, q, args...)
}
func TestOrganizationSQLPageBound(t *testing.T) {
	for driver, mk := range dialectsUnderTest(t) {
		t.Run(driver, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "search", Name: "search"}))
			for _, v := range []string{"a", "b", "c", "d"} {
				must(s.Organizations().Create(ctx, &store.Organization{TenantID: "search", ID: "org_" + strings.Repeat(v, 16), Name: v}, nil))
			}
			must(s.Clients().Create(ctx, &store.Client{TenantID: "search", ClientID: "client", Name: "client"}))
			for _, v := range []string{"a", "b", "c", "d"} {
				id := "org_" + strings.Repeat(v, 16)
				must(s.OrganizationsII().PutClients(ctx, "search", id, []store.OrganizationClient{{ClientID: "client", UseForMemberAccess: true}}))
			}
			orgID := "org_" + strings.Repeat("a", 16)
			for _, id := range []string{"conn-a", "conn-b", "conn-c"} {
				must(s.Connections().Create(ctx, &store.Connection{TenantID: "search", ID: id, Name: id, Strategy: "auth0"}))
				must(s.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: "search", OrganizationID: orgID, ConnectionID: id, ShowAsButton: true}, true))
			}
			counter := &orgQueryCounter{querier: s.q}
			s.q = counter
			got, e := s.Organizations().List(ctx, "search", store.OrgPage{PerPage: 2})
			must(e)
			if len(got.Items) != 2 || got.Total != 4 {
				t.Fatal(got)
			}
			selected := false
			for _, q := range counter.queries {
				if strings.Contains(q, "SELECT tenant_id, id") {
					selected = true
					if !strings.Contains(q, " LIMIT 2") {
						t.Fatalf("unbounded organization hydration: %s", q)
					}
				}
			}
			if !selected {
				t.Fatal(counter.queries)
			}
			counter.queries = nil
			annotated, e := s.Organizations().List(ctx, "search", store.OrgPage{PerPage: 2, IncludeClientAssociationFor: "client"})
			must(e)
			if len(counter.queries) != 3 {
				t.Fatalf("client summary queries %v", counter.queries)
			}
			for _, o := range annotated.Items {
				if o.ClientAssociation == nil || !o.ClientAssociation.UseForMemberAccess {
					t.Fatal(o)
				}
			}
			counter.queries = nil
			connections, e := s.Organizations().Connections(ctx, "search", orgID, store.OrgPage{PerPage: 2})
			must(e)
			if len(connections.Items) != 2 || connections.Total != 3 || len(counter.queries) != 4 {
				t.Fatalf("connection page %v; queries %v", connections, counter.queries)
			}
			for _, c := range connections.Items {
				if c.SummaryName != c.ConnectionID || c.SummaryStrategy != "auth0" {
					t.Fatal(c)
				}
			}
			counter.queries = nil
			q, e := orgsearch.Parse("", "lucene")
			must(e)
			res, e := s.OrganizationsII().Search(ctx, "search", q, store.OrganizationSearchPage{Take: 2, Sort: "name"})
			must(e)
			if len(res.Items) != 2 || res.Next == "" {
				t.Fatal(res)
			}
			if len(counter.queries) != 1 || !strings.Contains(counter.queries[0], " LIMIT 3") {
				t.Fatal(counter.queries)
			}
		})
	}
}
func TestOrganizationSearchParity(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.OrganizationSearchParity(t, func(t *testing.T) store.Store { return mk(t) })
		})
	}
}

func TestOrganizationSearchLegacyMetadataPresence(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			o := &store.Organization{TenantID: "t", ID: "org_aaaaaaaaaaaaaaaa", Name: "legacy"}
			must(s.Organizations().Create(ctx, o, nil))
			_, e := s.exec(ctx, `UPDATE organizations SET metadata=? WHERE tenant_id=?`, `{"empty":""}`, "t")
			must(e)
			for _, filter := range []string{`metadata.empty pr`, `metadata.empty eq ""`} {
				q, e := orgsearch.Parse(filter, "scim")
				must(e)
				r, e := s.OrganizationsII().Search(ctx, "t", q, store.OrganizationSearchPage{})
				must(e)
				if len(r.Items) != 1 {
					t.Fatalf("legacy empty %s: %v", filter, r)
				}
			}
		})
	}
}
