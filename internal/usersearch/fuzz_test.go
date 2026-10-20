package usersearch

import (
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// FuzzParse pins Review Focus 5: input typed into a console search box never
// panics, and every error is an *Error. A tree that parses is valid for the
// store.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"alice", "alice ", " alice", "alice+x@example.com", "a@b.c", "a b", `"abc`, `abc"`, `name:"abc`, `"`, `""`,
		"(", ")", "((", "))", "()", "(name:a", "name:a)", ")(", "name:", ":", "::", "email:", "email: x",
		"AND", "OR", "NOT", "-", "!", "--a", "!!a", "NOT NOT", "a AND", "AND a", "a OR", "OR a", "a AND OR b",
		`\`, `a\`, `name:a\`, `\*`, `*`, `**`, `name:*`, `name:**`, `*:*`, `_exists_:`, `_exists_:email`,
		`[1 TO 2]`, `logins_count:[1 TO`, `logins_count:[1 TO 2`, `logins_count:{*}`, `logins_count:[* TO *]`,
		`logins_count:>`, `logins_count:>=`, `logins_count:<=5`, `created_at:[2026-01-01 TO 2026-12-31]`,
		`app_metadata:x`, `app_metadata.:x`, `app_metadata..a:x`, `app_metadata.a:[1 TO 2]`, `user_metadata.a:b*`,
		"name:\x00", "name:\xff\xfe", "éè", "name:é*", "a\tb\nc", `name:(a OR (b AND c))`, `name:(`,
		`user_id:auth0\|x`, `user_id:"auth0|x"`, `bogus:1`, `a:b:c`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		tree, err := Parse(q)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Parse(%q) error %T is not *Error", q, err)
			}
			if e.Message == "" {
				t.Fatalf("Parse(%q): empty message", q)
			}
			return
		}
		if err := tree.Validate(); err != nil {
			t.Fatalf("Parse(%q) built a tree the store refuses: %v", q, err)
		}
		_, _ = store.NewUserMatcher(tree)
	})
}
