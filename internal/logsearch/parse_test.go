package logsearch

import (
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLogSearch(t *testing.T) {
	e := store.LogEvent{Type: "f", UserID: "auth0|abc", Date: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), Body: []byte(`{"client_name":"My App","description":"100%_!done","user_name":"Alice"}`)}
	for _, s := range []string{`type:f`, `type:(s OR f)`, `user_id:"auth0|abc"`, `date:[2026-10-01 TO 2026-10-30]`, `client_name:My*`, `NOT type:sapi`, `NOT hostname:any`, `description:100%_!*`, `Alice`, `type:f AND (client_name:My* OR type:s)`} {
		t.Run(s, func(t *testing.T) {
			q, err := Parse(s)
			if err != nil {
				t.Fatal(err)
			}
			if !Match(q, e) {
				t.Fatal("did not match")
			}
			for _, d := range []string{"sqlite", "postgres", "mysql"} {
				w, a, err := SQL(q, d)
				if err != nil || w == "" || len(a) == 0 {
					t.Fatalf("SQL %s %s %v %v", d, w, a, err)
				}
			}
		})
	}
	for _, s := range []string{`type:s`, `NOT type:f`, `client_name:my*`, `date:{2026-10-30 TO 2026-10-30}`} {
		q, err := Parse(s)
		if err != nil {
			t.Fatal(s, err)
		}
		if Match(q, e) {
			t.Fatalf("unexpected match %s", s)
		}
	}
}
func TestLogSearchRejects(t *testing.T) {
	for _, s := range []string{`type:*f`, `type:f~`, `type:/f/`, `password:x`, `unknown:(type:f)`, strings.Repeat("(", 17) + `type:f` + strings.Repeat(")", 17), strings.Repeat("x", 1001), `type:(s OR)`, `type:s type:f`, `type:s OR type:s OR type:s OR type:s OR type:s OR type:s`, `date:[oops TO *]`, `type:foo?`} {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func FuzzLogQuery(f *testing.F) {
	for _, s := range []string{"", `type:f`, `NOT type:(f OR s)`, `date:[2026-10-01 TO 2026-10-30]`, `user_name:"a%b"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q, err := Parse(s)
		if err != nil {
			return
		}
		if err := Validate(q); err != nil {
			t.Fatal(err)
		}
		_ = Match(q, store.LogEvent{})
		for _, d := range []string{"sqlite", "postgres", "mysql"} {
			if _, _, err := SQL(q, d); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// Public search syntax documents ranges and log_id; fixed-width decimal IDs
// preserve the same ordering under memory and each SQL dialect's binary collation.
func TestLogIDRanges(t *testing.T) {
	id := store.FormatLogID(2)
	event := store.LogEvent{ID: id}
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`log_id:[` + id + ` TO *]`, true},
		{`log_id:[* TO ` + id + `]`, true},
		{`log_id:[` + id + ` TO ` + id + `]`, true},
		{`log_id:{` + id + ` TO *]`, false},
		{`log_id:[* TO ` + id + `}`, false},
		{`log_id:[` + store.FormatLogID(3) + ` TO *]`, false},
	} {
		q, err := Parse(tc.raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if got := Match(q, event); got != tc.want {
			t.Fatalf("%s: got%v want%v", tc.raw, got, tc.want)
		}
		for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
			where, args, err := SQL(q, dialect)
			if err != nil || !strings.Contains(where, "log_id") || len(args) == 0 {
				t.Fatalf("%s: %s %v %v", dialect, where, args, err)
			}
		}
	}
	for _, raw := range []string{`log_id:[1 TO *]`, `log_id:[` + strings.Repeat("x", 56) + ` TO *]`, `type:[f TO s]`} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
