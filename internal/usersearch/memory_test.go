package usersearch_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/usersearch"
)

// TestParserAgreesWithStore runs parsed queries through the memory store.
func TestParserAgreesWithStore(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	login := base.Add(time.Hour)
	users := []*store.User{
		{UserID: "auth0|a", Email: "alice@example.com", Name: "Alice Obs", GivenName: "Alice", FamilyName: "Obs", Nickname: "al",
			AppMetadata: map[string]any{"plan": "pro", "tier": 2}, UserMetadata: map[string]any{"color": "red", "tags": []any{"x", "y"}},
			EmailVerified: true, LoginsCount: 3, LastLogin: &login},
		{UserID: "auth0|b", Email: "bob@other.org", Name: "Bob", Nickname: "bobby", AppMetadata: map[string]any{"plan": "PRO", "tier": "2"}},
		{UserID: "auth0|c", Email: "carol+x@example.com", Name: "carol+x@example.com", Nickname: "carol+x",
			FamilyName: "Obs", AppMetadata: map[string]any{"plan": true}, Blocked: true},
		{UserID: "auth0|d", Name: "Dan", Nickname: "dan", Username: "dan"},
	}
	for i, u := range users {
		u.TenantID, u.CreatedAt, u.UpdatedAt = "t", base.Add(time.Duration(i)*24*time.Hour), base
		u.Identities = []store.Identity{{Connection: "db", Provider: "auth0", UserID: u.UserID[6:]}}
		if err := st.Users().Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		q    string
		want []string
	}{
		{"", []string{"a", "b", "c", "d"}},
		{"*", []string{"a", "b", "c", "d"}},
		{"alice", []string{"a"}},
		{"ALICE", []string{"a"}},
		{"example.com", []string{"a", "c"}},
		{"carol+x@example.com", []string{"c"}},
		{"ali", nil},
		{"ali*", []string{"a"}},
		{"alice ", []string{"a"}},
		{"alice bob", []string{"a", "b"}},
		{"Obs", []string{"a", "c"}},
		{`"alice obs"`, []string{"a"}},
		{`name:"alice obs" OR nickname:dan`, []string{"a", "d"}},
		{"name:alice", nil},
		{"email:*", []string{"a", "b", "c"}},
		{"email:*@example.com", []string{"a", "c"}},
		{`email:"alice*"`, nil},
		{"NOT family_name:obs", nil},
		{"NOT family_name:bogus", []string{"a", "c"}},
		{"NOT blocked:true", []string{"a", "b", "d"}},
		{"-email_verified:true", []string{"b", "c", "d"}},
		{"email_verified:maybe", []string{"b", "c", "d"}},
		{"logins_count:abc", []string{"b", "c", "d"}},
		{"logins_count:>=1", []string{"a"}},
		{"logins_count:[0 TO 3}", []string{"b", "c", "d"}},
		{"created_at:2026-10-20", []string{"b"}},
		{"created_at:[2026-10-20 TO *]", []string{"b", "c", "d"}},
		{"created_at:<2026-10-21", []string{"a", "b"}},
		{"last_login:[* TO *]", []string{"a"}},
		{"_exists_:last_login", []string{"a"}},
		{"app_metadata.plan:pro", []string{"a"}},
		{"app_metadata.plan:PRO", []string{"b"}},
		{"app_metadata.plan:true", []string{"c"}},
		{"app_metadata.tier:2", []string{"a"}},
		{`app_metadata.tier:"2"`, []string{"b"}},
		{"user_metadata.tags:y", []string{"a"}},
		{"NOT app_metadata.plan:pro", []string{"b", "c", "d"}},
		{"_exists_:user_metadata.color", []string{"a"}},
		{"identities.connection:DB", []string{"a", "b", "c", "d"}},
		{"identities.user_id:b", []string{"b"}},
		{"user_id:auth0\\|a", []string{"a"}},
		{`user_id:"auth0|a"`, []string{"a"}},
		{"email:(alice@example.com OR bob@other.org)", []string{"a", "b"}},
		{"(name:bob OR name:dan) AND NOT nickname:dan", []string{"b"}},
		{"username:dan", []string{"d"}},
	}
	for _, c := range cases {
		q, err := usersearch.Parse(c.q)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.q, err)
			continue
		}
		got, total, err := st.Users().List(ctx, "t", q, store.UserSort{Field: "user_id"}, store.Page{Limit: 100})
		if err != nil {
			t.Errorf("List(%q): %v", c.q, err)
			continue
		}
		var ids []string
		for _, u := range got {
			ids = append(ids, u.UserID[6:])
		}
		if !slices.Equal(ids, c.want) && !(len(ids) == 0 && len(c.want) == 0) || total != len(ids) {
			t.Errorf("query %q = %v (total %d); want %v", c.q, ids, total, c.want)
		}
	}
	// Sorting through ParseSort.
	s, err := usersearch.ParseSort("created_at:-1")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := st.Users().List(ctx, "t", nil, s, store.Page{Limit: 10})
	if err != nil || got[0].UserID != "auth0|d" {
		t.Errorf("sort created_at:-1 first = %v, %v", got[0].UserID, err)
	}
}
