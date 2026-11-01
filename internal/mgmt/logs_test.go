package mgmt_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLogsAPIPaging(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	if err := e.st.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: e.tn.ID, Type: "f", Date: time.Now(), Body: []byte(`{"type":"f","description":"failure","password":"secret"}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"per_page=101", "page=10&per_page=100", "fields=unknown", "wat=x", "q=" + url.QueryEscape(`type:*f`), "sort=type:1", "include_totals=x", "per_page=0"} {
		r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?"+s, nil, e.h.ListLogs)
		if r.Code != 400 || o.(map[string]any)["errorCode"] != "invalid_query_string" {
			t.Fatalf("%s %d %s", s, r.Code, r.Body)
		}
	}
	r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?include_totals=true&fields=log_id,type", nil, e.h.ListLogs)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	v := o.(map[string]any)
	a := v["logs"].([]any)
	if v["total"] != float64(1) || v["length"] != float64(1) || len(a[0].(map[string]any)) != 2 {
		t.Fatal(o)
	}
	r, o = e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs", nil, e.h.ListLogs)
	if r.Code != 200 || o.([]any)[0].(map[string]any)["password"] == "secret" {
		t.Fatal(r.Body)
	}
}
func TestLogsAPICheckpoint(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	e.h.Now = func() time.Time { return time.Now().Add(3 * time.Second) }
	for range 3 {
		if err := e.st.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: e.tn.ID, Type: "s", Date: time.Now(), Body: []byte(`{}`)}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?take=2&q=bad:&page=no&fields=bad&sort=bad&include_totals=no", nil, e.h.ListLogs)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	a := o.([]any)
	if len(a) != 2 || a[0].(map[string]any)["log_id"].(string) >= a[1].(map[string]any)["log_id"].(string) {
		t.Fatal(o)
	}
	id := a[0].(map[string]any)["log_id"].(string)
	r, o = e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?from="+id+"&take=1", nil, e.h.ListLogs)
	if r.Code != 200 || len(o.([]any)) != 1 || o.([]any)[0].(map[string]any)["log_id"] != a[1].(map[string]any)["log_id"] {
		t.Fatal(r.Body)
	}
	e.h.Now = time.Now
	r, o = e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?take=2", nil, e.h.ListLogs)
	if r.Code != 200 || len(o.([]any)) != 0 {
		t.Fatal(r.Body)
	}
}

// The pinned CLI adds a search selector while polling checkpoints. The
// checkpoint contract ignores every parameter except from/take, including
// unknown names and repetitions; page mode remains strict.
func TestLogsAPICheckpointIgnoresAllOtherParameters(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Now = func() time.Time { return time.Now().Add(3 * time.Second) }
	if err := e.st.Logs().AppendLogs(context.Background(), []store.LogEvent{{TenantID: e.tn.ID, Type: "f", Date: time.Now(), Body: []byte(`{"description":"CLI tail event"}`)}, {TenantID: e.tn.ID, Type: "f", Date: time.Now(), Body: []byte(`{"description":"CLI tail event"}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"from=" + store.FormatLogID(1) + "&take=100&search_engine=v3&q=*&sort=date:1",
		"take=1&unknown=x&unknown=y&search_engine=v3&search_engine=bad",
	} {
		r, out := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?"+query, nil, e.h.ListLogs)
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", query, r.Code, r.Body)
		}
		rows := out.([]any)
		if len(rows) != 1 || rows[0].(map[string]any)["description"] != "CLI tail event" {
			t.Fatal(out)
		}
	}
	for _, query := range []string{"search_engine=v3", "take=1&from=0&from=0", "take=1&take=1"} {
		r, _ := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?"+query, nil, e.h.ListLogs)
		if r.Code != 400 {
			t.Fatalf("%s: %d %s", query, r.Code, r.Body)
		}
	}
}
func TestLogsCrossTenant(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	if err := e.st.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: e.sys.ID, Date: time.Now(), Body: []byte(`{}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := e.st.Logs().SearchLogs(ctx, e.sys.ID, nil, store.LogPage{PerPage: 1})
	for _, id := range []string{rows[0].ID, "bad"} {
		r, _ := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetLog(w, r, id) })
		if r.Code != 404 {
			t.Fatal(r.Code, r.Body)
		}
	}
}

type unavailableLogStore struct{ store.Store }

func (unavailableLogStore) Logs() store.Logs { return store.UnimplementedLogs{} }
func TestLogsUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = unavailableLogStore{e.st}
	r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs", nil, e.h.ListLogs)
	if r.Code != 501 || o.(map[string]any)["errorCode"] != "logs_unavailable" {
		t.Fatal(r.Code, r.Body)
	}
}
func TestUserLogsScopes(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "logs@example.test"})
	id := u["user_id"].(string)
	fn := mgmt.Require("read:logs")(mgmt.Require("read:logs_users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.UserLogs(w, r, id) }))).ServeHTTP
	for _, s := range [][]string{{"read:logs"}, {"read:logs_users"}, {"read:logs", "read:logs_users"}} {
		r, _ := e.do(t, m2mCaller(s...), "GET", "/api/v2/users/"+url.PathEscape(id)+"/logs", nil, fn)
		want := 403
		if len(s) == 2 {
			want = 200
		}
		if r.Code != want {
			t.Fatal(r.Code, r.Body)
		}
	}
}

func TestLogsAPIRejects(t *testing.T) {
	e := newClientsEnv(t)
	for _, q := range []string{`type:*f`, `type:f~`, `type:/f/`, `password:x`, `unknown:(type:f)`, strings.Repeat("(", 17) + `type:f` + strings.Repeat(")", 17)} {
		r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?q="+url.QueryEscape(q), nil, e.h.ListLogs)
		if r.Code != 400 || o.(map[string]any)["errorCode"] != "invalid_query_string" {
			t.Fatalf("%s %d %s", q, r.Code, r.Body)
		}
	}
}
func TestUserLogsFiltering(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	u := e.mustCreate(t, map[string]any{"email": "filter@example.test"})
	id := u["user_id"].(string)
	for _, uid := range []string{id, "auth0|other"} {
		if err := e.st.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: e.tn.ID, UserID: uid, Type: "s", Date: time.Now(), Body: []byte(`{}`)}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	fn := func(w http.ResponseWriter, r *http.Request) { e.h.UserLogs(w, r, id) }
	r, o := e.do(t, m2mCaller("read:logs", "read:logs_users"), "GET", "/api/v2/users/"+url.PathEscape(id)+"/logs?include_totals=true", nil, fn)
	if r.Code != 200 || o.(map[string]any)["total"] != float64(1) {
		t.Fatal(r.Body)
	}
	if err := e.st.Users().Delete(ctx, e.tn.ID, id); err != nil {
		t.Fatal(err)
	}
	r, o = e.do(t, m2mCaller("read:logs", "read:logs_users"), "GET", "/api/v2/users/"+url.PathEscape(id)+"/logs", nil, fn)
	if r.Code != 404 || o.(map[string]any)["errorCode"] != "not_found" {
		t.Fatal(r.Code, r.Body)
	}
}
func TestLogsAPITotalsLimit(t *testing.T) {
	e := newClientsEnv(t)
	events := make([]store.LogEvent, 1002)
	for i := range events {
		events[i] = store.LogEvent{TenantID: e.tn.ID, Date: time.Now(), Type: "s", Body: []byte(`{}`)}
	}
	if err := e.st.Logs().AppendLogs(context.Background(), events, nil); err != nil {
		t.Fatal(err)
	}
	r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs?include_totals=true&per_page=100&page=9&fields=type&include_fields=false", nil, e.h.ListLogs)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	v := o.(map[string]any)
	if v["total"] != float64(1000) || v["length"] != float64(100) || v["start"] != float64(900) {
		t.Fatal(o)
	}
	if _, found := v["logs"].([]any)[0].(map[string]any)["type"]; found {
		t.Fatal("exclude projection ignored")
	}
}

func TestLogsAPIGetScrubs(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	events := []store.LogEvent{{TenantID: e.tn.ID, Date: time.Now(), Type: "s", Body: []byte(`{"description":"dynamic-secret","details":{"password":"never show","dynamic-secret":"secret-key"},"count":9007199254740993}`)}}
	if err := e.st.Logs().AppendLogs(ctx, events, nil); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.Logs().SearchLogs(ctx, e.tn.ID, nil, store.LogPage{PerPage: 1})
	if err != nil {
		t.Fatal(err)
	}
	id := rows[0].ID
	r, o := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetLog(w, r.WithContext(logscrub.WithValues(r.Context(), "dynamic-secret", id)), id)
	})
	if r.Code != 200 || o.(map[string]any)["log_id"] != id || strings.Contains(r.Body.String(), "dynamic-secret") || strings.Contains(r.Body.String(), "never show") || !strings.Contains(r.Body.String(), "9007199254740993") {
		t.Fatal(r.Code, r.Body)
	}
}

func TestShortCredentialEventGETPreservesSchema(t *testing.T) {
	e := newClientsEnv(t)
	ctx := logscrub.WithCredentials(context.Background(), "a")
	recorder := logs.NewRecorder(e.st, logs.Config{}, slog.New(slog.DiscardHandler))
	logs.RecordEvent(ctx, recorder, logs.Event{TenantID: e.tn.ID, Type: "ss", UserName: "a", Details: map[string]any{"a": "a"}, ExecutionIDs: []string{"exe_aaaaaaaaaaaaaaaaaaaaaaaa"}})
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.Logs().SearchLogs(ctx, e.tn.ID, nil, store.LogPage{PerPage: 1})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	id := rows[0].ID
	r, obj := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetLog(w, r.WithContext(logscrub.WithCredentials(r.Context(), "a")), id)
	})
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	body := obj.(map[string]any)
	if body["type"] != "ss" || body["log_id"] != id || body["user_name"] != logscrub.Marker {
		t.Fatal(body)
	}
	if _, err := time.Parse(time.RFC3339Nano, body["date"].(string)); err != nil {
		t.Fatal(err)
	}
	if body["details"].(map[string]any)["actions"].(map[string]any)["executions"].([]any)[0] != "exe_aaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatal(body)
	}
	if body["details"].(map[string]any)[logscrub.Marker] != logscrub.Marker {
		t.Fatal(body)
	}
}

func TestLogsAuthoritativeIDAlias(t *testing.T) {
	e := newClientsEnv(t)
	if err := e.st.Logs().AppendLogs(context.Background(), []store.LogEvent{{TenantID: e.tn.ID, Type: "f", Date: time.Now(), Body: []byte(`{"_id":"spoof","log_id":"spoof"}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"", "?fields=_id,log_id", "?fields=log_id&include_fields=false"} {
		r, out := e.call(t, e.tn, m2mCaller("read:logs"), "GET", "/api/v2/logs"+query, nil, e.h.ListLogs)
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
		item := out.([]any)[0].(map[string]any)
		if item["_id"] != store.FormatLogID(1) {
			t.Fatalf("alias=%v", item)
		}
		if query != "?fields=log_id&include_fields=false" && item["log_id"] != item["_id"] {
			t.Fatal(item)
		}
	}
}
