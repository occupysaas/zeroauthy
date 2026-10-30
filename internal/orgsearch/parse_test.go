package orgsearch

import (
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestOrganizationSearchParity(t *testing.T) {
	o := store.Organization{ID: "org_A", Name: "acme", DisplayName: `A "quoted" café`, Metadata: map[string]string{"team": "engineering", "empty": "", "num": "12"}, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, tc := range []struct {
		parser, q string
		want      bool
	}{
		{"lucene", `id:org_A`, true}, {"lucene", `id:org_a`, false},
		{"lucene", `display_name:"A \"quoted\" café"`, true}, {"lucene", `name:ac* AND metadata.team:*ineer*`, true},
		{"lucene", `created_at:[2025-01-01T00:00:00Z TO 2027-01-01T00:00:00Z]`, true},
		{"scim", `metadata.empty pr and (name eq "acme" or name eq "other")`, true},
		{"scim", `metadata.num eq 12`, true}, {"scim", `metadata.team ew "ring"`, true},
		{"scim", `display_name co "café"`, true}, {"scim", `metadata.missing ne "x"`, false},
		{"scim", `created_at ge "2026-01-01T00:00:00Z"`, true},
		{"lucene", `name:ACME`, false}, {"lucene", ``, true},
	} {
		t.Run(tc.parser+tc.q, func(t *testing.T) {
			q, e := Parse(tc.q, tc.parser)
			if e != nil {
				t.Fatal(e)
			}
			if got := Match(q, o); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
func TestOrganizationSearchLimits(t *testing.T) {
	for _, tc := range []struct {
		q, p string
		ok   bool
	}{
		{strings.Repeat(" ", 1000), "lucene", true}, {strings.Repeat(" ", 1001), "lucene", false},
		{`display_name:"` + strings.Repeat("é", 985) + `"`, "lucene", true},
		{`display_name:"` + strings.Repeat("é", 986) + `"`, "lucene", false},
		{`name:a AND name:b AND name:c AND name:d AND name:e`, "lucene", true},
		{`name:a AND name:b AND name:c AND name:d AND name:e AND name:f`, "lucene", false},
		{strings.Repeat("(", 15) + `name:a` + strings.Repeat(")", 15), "lucene", true},
		{strings.Repeat("(", 16) + `name:a` + strings.Repeat(")", 16), "lucene", false},
		{`name:*ab*`, "lucene", false}, {`name:*abc*`, "lucene", true}, {`name:/regex/`, "lucene", false},
		{`name:foo~1`, "lucene", false}, {`unknown:a`, "lucene", false}, {`metadata.a.b:x`, "lucene", false},
		{`name co "ab"`, "scim", false}, {`name eq null`, "scim", false}, {`created_at gt 12`, "scim", false},
		{`id sw "org"`, "scim", false}, {`name:a`, "other", false}, {`name:a?`, "lucene", false},
	} {
		_, e := Parse(tc.q, tc.p)
		if (e == nil) != tc.ok {
			t.Errorf("%q/%s: %v", tc.q, tc.p, e)
		}
	}
}
func FuzzOrganizationQuery(f *testing.F) {
	for _, q := range []string{`name:ac*`, `(name:a OR name:b)`, `metadata.team co "abc"`, `created_at:[* TO 2026-01-01T00:00:00Z]`, `display_name:"café"`} {
		f.Add(q)
	}
	f.Fuzz(func(t *testing.T, q string) {
		for _, p := range []string{"lucene", "scim"} {
			a, e := Parse(q, p)
			if e == nil {
				_ = Match(a, store.Organization{})
				if e = Validate(a); e != nil {
					t.Fatal(e)
				}
			}
		}
	})
}
