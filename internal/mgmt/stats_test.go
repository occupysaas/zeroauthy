package mgmt_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type statsHandlers interface {
	GetDailyStats(http.ResponseWriter, *http.Request)
	GetActiveUsers(http.ResponseWriter, *http.Request)
}

func statsAPI(t *testing.T, h *mgmt.Handlers) statsHandlers {
	t.Helper()
	a, ok := any(h).(statsHandlers)
	if !ok {
		t.Fatal("stats handlers are not implemented")
	}
	return a
}

func TestDailyStats(t *testing.T) {
	e := newClientsEnv(t)
	a := statsAPI(t, e.h)
	day := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if err := e.st.Logs().AppendLogs(t.Context(), nil, []store.DailyStatDelta{
		{TenantID: e.tn.ID, Day: day, Logins: 2, Signups: 1},
		{TenantID: e.tn.ID, Day: day, Logins: 1, LeakedPasswords: 2},
		{TenantID: e.tn.ID, Day: day.AddDate(0, 0, -2), Signups: 3},
		{TenantID: e.sys.ID, Day: day, Logins: 999},
	}); err != nil {
		t.Fatal(err)
	}
	w, out := e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/daily?from=20261028&to=20261030", nil, a.GetDailyStats)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	rows := out.([]any)
	if len(rows) != 3 {
		t.Fatal(out)
	}
	for i, raw := range rows {
		row := raw.(map[string]any)
		if len(row) != 6 || row["date"] != day.AddDate(0, 0, i-2).Format(time.RFC3339) {
			t.Fatal(row)
		}
		for _, k := range []string{"created_at", "updated_at"} {
			if _, err := time.Parse(time.RFC3339, row[k].(string)); err != nil {
				t.Fatal(row, err)
			}
		}
	}
	if row := rows[2].(map[string]any); row["logins"] != float64(3) || row["signups"] != float64(1) || row["leaked_passwords"] != float64(2) {
		t.Fatal(row)
	}
	if row := rows[1].(map[string]any); row["logins"] != float64(0) || row["signups"] != float64(0) || row["leaked_passwords"] != float64(0) || row["created_at"] != "2026-10-29T00:00:00Z" || row["updated_at"] != row["created_at"] {
		t.Fatal(row)
	}
}

func TestDailyStatsUTCWindow(t *testing.T) {
	e := newClientsEnv(t)
	a := statsAPI(t, e.h)
	// Local October 30 is already October 31 in UTC; defaults are independent.
	e.h.Now = func() time.Time { return time.Date(2026, 10, 30, 23, 30, 0, 0, time.FixedZone("west", -7*3600)) }
	for _, tc := range []struct {
		query, first, last string
		count              int
	}{
		{"", "2026-10-25", "2026-10-31", 7},
		{"from=20261029", "2026-10-29", "2026-10-31", 3},
		{"to=20261026", "2026-10-25", "2026-10-26", 2},
		{"from=20240101&to=20241231", "2024-01-01", "2024-12-31", 366},
		{"from=00000101&to=00000101", "0000-01-01", "0000-01-01", 1},
		{"from=99991231&to=99991231", "9999-12-31", "9999-12-31", 1},
	} {
		w, out := e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/daily?"+tc.query, nil, a.GetDailyStats)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body)
		}
		rows := out.([]any)
		if len(rows) != tc.count || rows[0].(map[string]any)["date"] != tc.first+"T00:00:00Z" || rows[len(rows)-1].(map[string]any)["date"] != tc.last+"T00:00:00Z" {
			t.Fatal(tc, out)
		}
	}
	for _, q := range []string{"from=", "to=", "from=20260229", "to=20261301", "from=2026-10-30", "from=2026103", "from=202610300", "from=20261031&to=20261030", "from=20240101&to=20250101", "from=00000101&to=99991231", "from=99999999999999999999999999", "from=-0010101", "from=20261030&from=20261030", "to=20261030&to=20261030", "page=0"} {
		w, out := e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/daily?"+q, nil, a.GetDailyStats)
		if w.Code != 400 || out.(map[string]any)["errorCode"] != "invalid_query_string" {
			t.Fatal(q, w.Code, w.Body)
		}
	}
}

func TestActiveUsers(t *testing.T) {
	e := newUsersEnv(t)
	a := statsAPI(t, e.h)
	clock := time.Date(2026, 10, 31, 12, 34, 56, 0, time.UTC)
	e.h.Now = func() time.Time { return clock }
	for i, ago := range []time.Duration{31 * 24 * time.Hour, 30*24*time.Hour + time.Nanosecond, 30 * 24 * time.Hour, time.Hour} {
		id := e.mustCreate(t, map[string]any{"email": []string{"old@x.test", "before@x.test", "boundary@x.test", "recent@x.test"}[i]})["user_id"].(string)
		if err := e.st.Users().RecordLogin(t.Context(), e.tn.ID, id, clock.Add(-ago), ""); err != nil {
			t.Fatal(err)
		}
	}
	e.mustCreate(t, map[string]any{"email": "never@x.test"})
	if err := e.st.Users().Create(t.Context(), &store.User{TenantID: e.sys.ID, UserID: "auth0|other", LastLogin: &clock}); err != nil {
		t.Fatal(err)
	}
	w, out := e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/active-users", nil, a.GetActiveUsers)
	if w.Code != 200 || out != float64(2) {
		t.Fatal(w.Code, w.Body)
	}
	for _, q := range []string{"from=20261030", "page=0", "q="} {
		w, out = e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/active-users?"+q, nil, a.GetActiveUsers)
		if w.Code != 400 || out.(map[string]any)["errorCode"] != "invalid_query_string" {
			t.Fatal(w.Code, w.Body)
		}
	}
}

func TestStatsScope(t *testing.T) {
	e := newClientsEnv(t)
	a := statsAPI(t, e.h)
	for _, fn := range []http.HandlerFunc{a.GetDailyStats, a.GetActiveUsers} {
		for _, tc := range []struct {
			caller mgmt.Caller
			want   int
		}{{m2mCaller("read:users"), 403}, {m2mCaller("read:stats"), 200}} {
			w, _ := e.call(t, e.tn, tc.caller, "GET", "/api/v2/stats/daily", nil, mgmt.Require("read:stats")(fn).ServeHTTP)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body)
			}
		}
	}
}

func TestDailyStatsAndActiveUsersUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = unavailableLogStore{e.st}
	a := statsAPI(t, e.h)
	for _, fn := range []http.HandlerFunc{a.GetDailyStats, a.GetActiveUsers} {
		w, out := e.call(t, e.tn, m2mCaller("read:stats"), "GET", "/api/v2/stats/daily", nil, fn)
		if w.Code != 501 || out.(map[string]any)["errorCode"] != "logs_unavailable" {
			t.Fatal(w.Code, w.Body)
		}
	}
}
