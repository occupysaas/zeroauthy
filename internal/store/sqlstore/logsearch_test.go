package sqlstore

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestLogSearchParity(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			m := memory.New()
			ctx := context.Background()
			for _, st := range []store.Store{s, m} {
				if err := st.Tenants().Create(ctx, &store.Tenant{ID: "search", Name: "search"}); err != nil {
					t.Fatal(err)
				}
				if err := st.Tenants().Create(ctx, &store.Tenant{ID: "other", Name: "other"}); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 30, 12, 0, 0, 123456789, time.UTC)
			events := []store.LogEvent{{TenantID: "search", Date: at, Type: "f", UserID: "auth0|abc", Body: []byte(`{"client_name":"My App","description":"100%_!done","user_name":"Alice","hostname":null}`)}, {TenantID: "search", Date: at.Add(-time.Hour * 24 * 60), Type: "s", UserID: "other", Body: []byte(`{"client_name":"my App","description":"100XXXdone","hostname":"present"}`)}, {TenantID: "search", Date: at, Type: "sapi", Body: []byte(`{"hostname":12,"client_name":"My_other"}`)}, {TenantID: "other", Date: at, Type: "f", Body: []byte(`{}`)}, {TenantID: "search", Date: at.Add(time.Second), Type: "s"}}
			for _, st := range []store.Store{s, m} {
				if err := st.Logs().AppendLogs(ctx, events, nil); err != nil {
					t.Fatal(err)
				}
			}
			queries := []string{`type:f`, `type:(s OR f)`, `user_id:"auth0|abc"`, `date:[2026-10-01 TO 2026-10-30]`, `client_name:My*`, `NOT type:sapi`, `NOT hostname:any`, `hostname:12`, `NOT hostname:present`, `description:100%_!*`, `client_name:My_*`, `Alice`, `NOT user_name:Alice`, `type:f OR type:s AND user_id:other`, `date:"2026-10-30T12:00:00.123456789Z"`, `date:{2026-10-30T12:00:00.123456788Z TO *]`, `date:[* TO 2026-10-30T12:00:00.123456788Z]`}
			for _, raw := range queries {
				t.Run(raw, func(t *testing.T) {
					q, err := logsearch.Parse(raw)
					if err != nil {
						t.Fatal(err)
					}
					p := store.LogPage{PerPage: 100, Ascending: true, IncludeTotals: true}
					got, total, err := s.Logs().SearchLogs(ctx, "search", q, p)
					if err != nil {
						t.Fatal(err)
					}
					want, wt, err := m.Logs().SearchLogs(ctx, "search", q, p)
					if err != nil {
						t.Fatal(err)
					}
					ids := func(es []store.LogEvent) []string {
						v := []string{}
						for _, e := range es {
							v = append(v, e.ID)
						}
						return v
					}
					if !reflect.DeepEqual(ids(got), ids(want)) || total != wt {
						t.Fatalf("got %v total%d want %v total%d", ids(got), total, ids(want), wt)
					}
					for _, latest := range []bool{false, true} {
						var g, w []store.LogEvent
						if latest {
							g, err = s.Logs().LatestLogs(ctx, "search", q, 2, time.Now().Add(time.Hour))
							w, _ = m.Logs().LatestLogs(ctx, "search", q, 2, time.Now().Add(time.Hour))
						} else {
							g, err = s.Logs().LogsAfter(ctx, "search", 0, q, 2, time.Now().Add(time.Hour))
							w, _ = m.Logs().LogsAfter(ctx, "search", 0, q, 2, time.Now().Add(time.Hour))
						}
						if err != nil || !reflect.DeepEqual(ids(g), ids(w)) {
							t.Fatalf("checkpoint latest%v got%v want%v err%v", latest, ids(g), ids(w), err)
						}
					}
				})
			}
		})
	}
}

func TestLogSearchAcceptedJSON(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			m := memory.New()
			for _, st := range []store.Store{s, m} {
				if err := st.Tenants().Create(ctx, &store.Tenant{ID: "json", Name: "json"}); err != nil {
					t.Fatal(err)
				}
			}
			bodies := []string{`{"client_name":"My App","details":{"value":"\u0000"}}`, `{"client_name":"My App","details":{"value":"\ud800"}}`, `{"client_name":"My App","details":{"value":1e1000000}}`, `{"client_name":"My\u0000App"}`, `{"client_name":"My\ud800App"}`, `{"client_name":1e1000000}`, `{"client_name":"My App","details":{"value":` + strings.Repeat("9", 150000) + `}}`}
			for _, body := range bodies {
				before, _, err := s.Logs().SearchLogs(ctx, "json", nil, store.LogPage{PerPage: 100})
				if err != nil {
					t.Fatal(err)
				}
				for _, st := range []store.Store{s, m} {
					if err := st.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "json", Date: time.Now(), Type: "s", Body: []byte(body)}}, nil); err != nil {
						t.Fatal(err)
					}
				}
				after, _, err := s.Logs().SearchLogs(ctx, "json", nil, store.LogPage{PerPage: 100})
				if err != nil {
					t.Fatal(err)
				}
				if len(after) != len(before)+1 || !bytes.Equal(after[0].Body, []byte(body)) {
					t.Fatal("append mutated body")
				}
			}
			ids := func(es []store.LogEvent) []string {
				out := []string{}
				for _, e := range es {
					out = append(out, e.ID)
				}
				return out
			}
			for _, tc := range []struct {
				raw   string
				total int
			}{{`client_name:My*`, 6}, {`client_name:"My App"`, 4}, {`NOT client_name:My*`, 1}, {`NOT hostname:any`, 7}, {`My*`, 6}, {`client_name:"My�App"`, 1}, {`client_name:"1e1000000"`, 0}} {
				t.Run(tc.raw, func(t *testing.T) {
					q, err := logsearch.Parse(tc.raw)
					if err != nil {
						t.Fatal(err)
					}
					p := store.LogPage{PerPage: 100, Ascending: true, IncludeTotals: true}
					got, total, err := s.Logs().SearchLogs(ctx, "json", q, p)
					if err != nil {
						t.Fatal(err)
					}
					want, wt, err := m.Logs().SearchLogs(ctx, "json", q, p)
					if err != nil {
						t.Fatal(err)
					}
					if total != tc.total || total != wt || !reflect.DeepEqual(ids(got), ids(want)) {
						t.Fatalf("got%v/%d want%v/%d", ids(got), total, ids(want), wt)
					}
				})
			}
		})
	}
}

func TestLogSearchBodyValidation(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.LogBodyValidation(t, func(t *testing.T) store.Store { return fresh(t) }) })
	}
}

func TestLogSearchMigration29(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := openAtVersion(t, mk(t), 28)
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "backfill", Name: "backfill"}); err != nil {
				t.Fatal(err)
			}
			at := logTime(time.Now())
			body := []byte(`{"client_name":"My App","details":{"v":"\u0000","n":1e1000000}}`)
			for i := range 103 {
				b := body
				if i == 102 {
					b = []byte(`{"client_name":"My\u0000App"}`)
				}
				if _, err := s.exec(ctx, `INSERT INTO tenant_logs (tenant_id,log_id,date,committed_at,type,user_id,client_id,connection_id,organization_id,ip,body) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, "backfill", store.FormatLogID(int64(i+1)), at, at, "s", "", "", "", "", "", b); err != nil {
					t.Fatal(err)
				}
			}
			if name == "mysql" {
				// Simulate a process stopping after MySQL's implicit-commit DDL.
				ddl, err := migrationFiles.ReadFile("migrations/mysql/0029_log_search.sql")
				if err != nil {
					t.Fatal(err)
				}
				for _, stmt := range splitStatements(string(ddl)) {
					if _, err := s.exec(ctx, stmt); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			v, err := s.SchemaVersion(ctx)
			if err != nil || v != 29 {
				t.Fatalf("version=%d err=%v", v, err)
			}
			for _, tc := range []struct {
				raw   string
				total int
			}{{`client_name:My*`, 103}, {`client_name:"My App"`, 102}, {`NOT client_name:My*`, 0}} {
				q, err := logsearch.Parse(tc.raw)
				if err != nil {
					t.Fatal(err)
				}
				rows, total, err := s.Logs().SearchLogs(ctx, "backfill", q, store.LogPage{PerPage: 100, IncludeTotals: true})
				if err != nil || total != tc.total || len(rows) != min(tc.total, 100) {
					t.Fatalf("%s total%d rows%d err%v", tc.raw, total, len(rows), err)
				}
			}
			row, err := s.Logs().GetLog(ctx, "backfill", store.FormatLogID(1))
			if err != nil || !bytes.Equal(row.Body, body) {
				t.Fatalf("backfill changed bytes err%v", err)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
