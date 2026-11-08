package sqlstore

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// TestWebAuthnMigrationLeavesRows checks that 0035 only adds NULL columns and
// a table: rows written at 0034 read back identical, with the new columns NULL.
func TestWebAuthnMigrationLeavesRows(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 34)
			mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('t','t','T','','[]','[]','{}',0,0,'','','',1)`)
			mustExec(t, s, `INSERT INTO mfa_authenticators (tenant_id,id,user_id,type,credential_id,name,confirmed,preferred,public_data,last_step,code_hash,email,phone,public_key,rp_id,sign_count,created_at,last_auth_at) VALUES ('t','webauthn-roaming|dev_1','auth0|u','webauthn-roaming',?,'Key',true,false,?,0,'','','',?,'t.example.test',7,1,2)`,
				[]byte("cred"), []byte(`{"aaguid":"00000000-0000-0000-0000-000000000000"}`), []byte{0xa1, 0x01, 0x02})
			snapshot := func(table, order, tag string) ([]string, [][]any) {
				// tag varies the statement text: PostgreSQL's statement cache
				// would otherwise reuse the pre-migration result shape.
				rows, err := s.query(ctx, `SELECT * FROM `+table+` ORDER BY `+order+` /* `+tag+` */`)
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
				return cols, out
			}
			tables := map[string]string{"tenants": "id", "mfa_authenticators": "id"}
			beforeCols, before := map[string][]string{}, map[string][][]any{}
			for tbl, order := range tables {
				beforeCols[tbl], before[tbl] = snapshot(tbl, order, "before")
			}
			if err := s.migrateTo(ctx, 35); err != nil {
				t.Fatal(err)
			}
			for tbl, order := range tables {
				cols, after := snapshot(tbl, order, "after")
				byName := func(cols []string, row []any) map[string]any {
					m := map[string]any{}
					for i, c := range cols {
						m[c] = row[i]
					}
					return m
				}
				for i := range before[tbl] {
					b, a := byName(beforeCols[tbl], before[tbl][i]), byName(cols, after[i])
					for c, v := range a {
						old, existed := b[c]
						if existed && !reflect.DeepEqual(old, v) {
							t.Errorf("%s.%s changed: %v -> %v", tbl, c, old, v)
						}
						if !existed && v != nil {
							t.Errorf("%s.%s new column not NULL: %v", tbl, c, v)
						}
					}
				}
			}
			for _, tbl := range []string{"sessions", "clients", "webauthn_snoozes"} {
				var n int
				if err := s.queryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tbl)).Scan(&n); err != nil {
					t.Fatalf("%s: %v", tbl, err)
				}
			}
		})
	}
}
