package storetest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// OrganizationSearchParity runs identical parser, ordering, tenant and keyset
// cases through a repository factory, including plugin transports.
func OrganizationSearchParity(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	orgSeed(t, s, true)
	ids := []string{"org_search0000000001", "org_search0000000002", "org_search0000000003"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 123000000, time.UTC)
	fixtures := []store.Organization{
		{TenantID: "org-a", ID: ids[0], Name: "search-a", DisplayName: `A "quoted" café`, Metadata: map[string]string{"team": "Engineering", "wild": "a%_!b", "path": `a\b`, "num": "12"}, CreatedAt: base},
		{TenantID: "org-a", ID: ids[1], Name: "search-b", DisplayName: `Same`, Metadata: map[string]string{"team": "engineering", "num": "2"}, CreatedAt: base},
		{TenantID: "org-a", ID: ids[2], Name: "search-c", DisplayName: `Same`, Metadata: map[string]string{"team": "sales"}, CreatedAt: base.Add(time.Second)},
	}
	for _, o := range fixtures {
		v := o
		mustNoErr(t, s.Organizations().Create(ctx, &v, nil))
	}
	other := fixtures[0]
	other.TenantID = "org-b"
	mustNoErr(t, s.Organizations().Create(ctx, &other, nil))
	for _, tc := range []struct {
		p, q string
		want []string
	}{
		{"lucene", "", ids}, {"lucene", `id:` + ids[0], ids[:1]}, {"lucene", `id:ORG_search0000000001`, nil},
		{"lucene", `display_name:"A \"quoted\" café"`, ids[:1]},
		{"lucene", `name:search-* AND metadata.team:*ineer*`, ids[:2]},
		{"lucene", `metadata.team:Engineering`, ids[:1]},
		{"scim", `metadata.team eq "engineering"`, ids[1:2]},
		{"scim", `metadata.team ew "ring"`, ids[:2]},
		{"scim", `metadata.team sw "Eng"`, ids[:1]},
		{"scim", `metadata.wild co "%_!"`, ids[:1]},
		{"scim", `metadata.path eq "a\\b"`, ids[:1]},
		{"scim", `metadata.num eq 12`, ids[:1]},
		{"scim", `metadata.num pr and (metadata.num lt 2 or name eq "search-b")`, ids[:2]},
		{"scim", `metadata.missing ne "x"`, nil},
		{"scim", `display_name co "caf\u00e9"`, ids[:1]},
		{"lucene", `created_at:[2026-01-01T00:00:00.123Z TO 2026-01-01T00:00:00.123Z]`, ids[:2]},
		{"lucene", `created_at:{2026-01-01T00:00:00.123Z TO *}`, ids[2:]},
		{"scim", `created_at ge "2026-01-01T00:00:01Z"`, ids[2:]},
		{"scim", `created_at eq "2026-01-01T00:00:00.123000001Z"`, nil},
		{"scim", `created_at gt "2026-01-01T00:00:00.122999999Z"`, ids},
		{"scim", `created_at ge "2026-01-01T00:00:00.123000001Z"`, ids[2:]},
		{"scim", `created_at lt "2026-01-01T00:00:00.123000001Z"`, ids[:2]},
		{"scim", `created_at le "2026-01-01T00:00:00.122999999Z"`, nil},
		{"scim", `metadata.team co "Eng"`, ids[:1]},
		{"lucene", `name:search-b OR name:search-c AND metadata.team:sales`, ids[1:]},
	} {
		t.Run(tc.p+tc.q, func(t *testing.T) {
			q, e := orgsearch.Parse(tc.q, tc.p)
			mustNoErr(t, e)
			got, e := s.OrganizationsII().Search(ctx, "org-a", q, store.OrganizationSearchPage{Sort: "name"})
			mustNoErr(t, e)
			var actual []string
			for _, o := range got.Items {
				actual = append(actual, o.ID)
			}
			if !reflect.DeepEqual(actual, tc.want) {
				t.Fatalf("IDs %v want %v", actual, tc.want)
			}
		})
	}
	for _, sort := range []string{"name", "display_name", "created_at"} {
		t.Run("keyset/"+sort, func(t *testing.T) {
			p := store.OrganizationSearchPage{Take: 1, Sort: sort}
			var got []string
			for i := 0; i < 4; i++ {
				res, e := s.OrganizationsII().Search(ctx, "org-a", store.OrganizationQuery{}, p)
				mustNoErr(t, e)
				if len(res.Items) != 1 {
					t.Fatal(res)
				}
				o := res.Items[0]
				got = append(got, o.ID)
				if res.Next == "" {
					break
				}
				p.LastID, p.LastValue = o.ID, orgsearch.SortValue(o, sort)
			}
			if !reflect.DeepEqual(got, ids) {
				t.Fatalf("keyset %v", got)
			}
		})
	}
	for _, q := range []store.OrganizationQuery{{Field: "name); DROP TABLE organizations;--", Op: "eq", Value: "x"}, {Field: "name", Op: "regex", Value: "x"}, {Field: "metadata.x", Op: "co", Value: "ab"}, {Op: "and"}} {
		if _, e := s.OrganizationsII().Search(ctx, "org-a", q, store.OrganizationSearchPage{}); !errors.Is(e, store.ErrInvalid) {
			t.Fatalf("invalid AST accepted: %v", e)
		}
	}
	for _, p := range []store.OrganizationSearchPage{{Take: -1}, {Take: 101}, {Sort: "name:1"}, {LastValue: "x"}, {LastID: "x", LastValue: "invalid"}} {
		if _, e := s.OrganizationsII().Search(ctx, "org-a", store.OrganizationQuery{}, p); !errors.Is(e, store.ErrInvalid) {
			t.Fatalf("invalid page accepted: %v", e)
		}
	}
}
