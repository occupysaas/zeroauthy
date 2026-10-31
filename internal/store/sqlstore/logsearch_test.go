package sqlstore

import (
	"context"
	"reflect"
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

func TestLogSearchBodyValidation(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.LogBodyValidation(t, func(t *testing.T) store.Store { return fresh(t) }) })
	}
}
