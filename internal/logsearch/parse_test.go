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
