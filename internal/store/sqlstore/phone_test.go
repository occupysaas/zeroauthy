package sqlstore

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Catches a 0034 migration that rewrites existing user rows (for example by
// backfilling phone_normalized), or that fails on odd or duplicate numbers.
func TestPhoneMigrationLeavesUserData(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 33)
			mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('t','t','','','[]','[]','{}',0,0,'','','',1)`)
			phones := []string{"+14155550100", "+14155550100", "(415) 555-0100", "00 44 7700 900123", "not a number", ""}
			for i, p := range phones {
				insertLegacyUser(t, s, &store.User{TenantID: "t", UserID: "auth0|u" + string(rune('a'+i)), Email: "u@example.test", PhoneNumber: p,
					Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "u"}}})
			}
			snapshot := func() [][]any {
				rows, err := s.query(ctx, `SELECT `+userColsBeforeActionsII+`, last_password_reset, remember_browser_epoch FROM users ORDER BY user_id`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				cols, _ := rows.Columns()
				var out [][]any
				for rows.Next() {
					vals := make([]any, len(cols))
					ptrs := make([]any, len(cols))
					for i := range vals {
						ptrs[i] = &vals[i]
					}
					if err := rows.Scan(ptrs...); err != nil {
						t.Fatal(err)
					}
					for i, v := range vals {
						if b, ok := v.([]byte); ok {
							vals[i] = string(b)
						}
					}
					out = append(out, vals)
				}
				return out
			}
			before := snapshot()
			if len(before) != len(phones) {
				t.Fatalf("seeded %d", len(before))
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if after := snapshot(); !reflect.DeepEqual(before, after) {
				t.Fatalf("user rows changed by migration:\n%v\n%v", before, after)
			}
			var n int
			if err := s.queryRow(ctx, `SELECT COUNT(*) FROM users WHERE phone_normalized IS NOT NULL`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("phone_normalized backfilled for %d rows (err %v)", n, err)
			}
			got, err := s.Users().Get(ctx, "t", "auth0|ua")
			if err != nil || got.PhoneNormalized != "" || got.PhoneNumber != "+14155550100" {
				t.Fatalf("legacy user: %+v %v", got, err)
			}
		})
	}
}

// A phone-signup proof has no encrypted continuation payload. SQL JSON null
// must remain absent, or the caller attempts to decrypt an empty ciphertext
// after spending a valid code.
func TestPhoneCodeAbsentRequestRoundTrip(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := t.Context()
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "phone-null", Name: "phone-null"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			code := &store.PasswordlessCode{TenantID: "phone-null", ConnectionID: "db", Identifier: "+14155553430", Kind: "phone-signup", CodeHash: "proof", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
			if err := s.Phone().PutPasswordlessCode(ctx, code); err != nil {
				t.Fatal(err)
			}
			got, err := s.Phone().ConsumePasswordlessCode(ctx, code.TenantID, code.ConnectionID, code.Identifier, code.Kind, code.CodeHash, 3, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Request) != 0 {
				t.Fatalf("absent payload became %q", got.Request)
			}
		})
	}
}
