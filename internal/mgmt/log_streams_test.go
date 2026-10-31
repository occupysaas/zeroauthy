package mgmt_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type streamAPI interface {
	ListLogStreams(http.ResponseWriter, *http.Request)
	CreateLogStream(http.ResponseWriter, *http.Request)
	GetLogStream(http.ResponseWriter, *http.Request, string)
	UpdateLogStream(http.ResponseWriter, *http.Request, string)
	DeleteLogStream(http.ResponseWriter, *http.Request, string)
}

func streamHandler(t *testing.T, e *clientsEnv, method, id string) http.HandlerFunc {
	t.Helper()
	api, ok := any(e.h).(streamAPI)
	if !ok {
		t.Fatal("Log stream Management handlers are missing")
	}
	switch method {
	case "POST":
		return api.CreateLogStream
	case "GET":
		if id == "" {
			return api.ListLogStreams
		}
		return func(w http.ResponseWriter, r *http.Request) { api.GetLogStream(w, r, id) }
	case "PATCH":
		return func(w http.ResponseWriter, r *http.Request) { api.UpdateLogStream(w, r, id) }
	case "DELETE":
		return func(w http.ResponseWriter, r *http.Request) { api.DeleteLogStream(w, r, id) }
	}
	t.Fatal("bad test method")
	return nil
}
func streamCall(t *testing.T, e *clientsEnv, method, id string, body any) (*httptest.ResponseRecorder, any) {
	t.Helper()
	p := "/api/v2/log-streams"
	if id != "" {
		p += "/" + id
	}
	return e.call(t, e.tn, m2mCaller(), method, p, body, streamHandler(t, e, method, id))
}
func streamSink(typ string) map[string]any {
	switch typ {
	case "http":
		return map[string]any{"httpEndpoint": "https://collector.example.test/logs", "httpAuthorization": "SENTINEL_http_secret", "httpCustomHeaders": []any{map[string]any{"header": "X-Key", "value": "SENTINEL_header_secret"}}, "httpContentFormat": "JSONLINES"}
	case "datadog":
		return map[string]any{"datadogApiKey": "SENTINEL_datadog_secret", "datadogRegion": "us"}
	case "splunk":
		return map[string]any{"splunkDomain": "collector.example.test", "splunkPort": "8088", "splunkSecure": true, "splunkToken": "SENTINEL_splunk_secret"}
	case "sumo":
		return map[string]any{"sumoSourceAddress": "https://collector.example.test/SENTINEL_sumo_secret"}
	case "segment":
		return map[string]any{"segmentWriteKey": "SENTINEL_segment_secret"}
	case "mixpanel":
		return map[string]any{"mixpanelRegion": "eu", "mixpanelProjectId": "123", "mixpanelServiceAccountUsername": "service", "mixpanelServiceAccountPassword": "SENTINEL_mixpanel_secret"}
	case "eventbridge":
		return map[string]any{"awsAccountId": "123456789012", "awsRegion": "us-east-1"}
	case "eventgrid":
		return map[string]any{"azureSubscriptionId": "12345678-1234-1234-1234-123456789012", "azureRegion": "eastus", "azureResourceGroup": "group"}
	}
	panic(typ)
}
func streamCreate(t *testing.T, e *clientsEnv, typ string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"type": typ, "name": "Example", "sink": streamSink(typ)}
	for k, v := range extra {
		body[k] = v
	}
	w, out := streamCall(t, e, "POST", "", body)
	if w.Code != 200 {
		t.Fatalf("create %s: %d %s", typ, w.Code, w.Body)
	}
	id, _ := out.(map[string]any)["id"].(string)
	if id == "" {
		t.Fatal("missing ID")
	}
	return id
}
func streamSecrets(t *testing.T, e *clientsEnv, s *store.LogStream) map[string]any {
	t.Helper()
	if len(s.SealedSecrets) == 0 {
		return map[string]any{}
	}
	raw, err := keys.OpenBound(e.w, "log-stream/v1", []string{s.TenantID, s.ID, s.Type}, s.SealedSecrets)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid secret envelope")
	}
	return result
}
func TestLogStreamCRUD(t *testing.T) {
	for _, schema := range logrules.Inventory().Sinks {
		t.Run(schema.Type, func(t *testing.T) {
			e := newClientsEnv(t)
			logSetup(e)
			id := streamCreate(t, e, schema.Type, nil)
			w, out := streamCall(t, e, "GET", id, nil)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			view := out.(map[string]any)
			sink := view["sink"].(map[string]any)
			saved, err := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
			if err != nil {
				t.Fatal(err)
			}
			secrets := streamSecrets(t, e, saved)
			for _, f := range schema.Fields {
				if _, exists := streamSink(schema.Type)[f.Name]; exists && f.Secret {
					if sink[f.Name] != logrules.Marker || saved.Sink[f.Name] != nil || !reflect.DeepEqual(secrets[f.Name], streamSink(schema.Type)[f.Name]) {
						t.Fatalf("secret %s not sealed/redacted: view=%v public=%v", f.Name, sink, saved.Sink)
					}
				}
			}
			if view["startFrom"] != nil || view["SealedSecrets"] != nil {
				t.Fatal("private field in view")
			}
			list, items := streamCall(t, e, "GET", "", nil)
			if list.Code != 200 || len(items.([]any)) != 1 || strings.Contains(list.Body.String(), "SENTINEL_") {
				t.Fatal(list.Code, list.Body)
			}
			for _, patch := range []any{map[string]any{"name": "Renamed"}, map[string]any{"sink": map[string]any{}}, map[string]any{"sink": sink}} {
				w, _ = streamCall(t, e, "PATCH", id, patch)
				if w.Code != 200 || strings.Contains(w.Body.String(), "SENTINEL_") {
					t.Fatal(w.Code, w.Body)
				}
			}
			after, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
			if !reflect.DeepEqual(secrets, streamSecrets(t, e, after)) {
				t.Fatal("PATCH did not retain omitted/marker secrets")
			}
			for _, bad := range []any{map[string]any{"type": schema.Type}, map[string]any{"sink": map[string]any{"unknown": "x"}}, map[string]any{"startFrom": time.Now().Format(time.RFC3339)}, map[string]any{"filters": []any{map[string]any{"type": "category", "name": "s"}}}, map[string]any{"filters": []any{map[string]any{"type": "event", "name": "auth.login.success"}}}, map[string]any{"pii_config": map[string]any{"log_fields": []string{"password"}}}, map[string]any{"pii_config": map[string]any{"log_fields": []string{"email"}, "method": "encrypt"}}, map[string]any{"pii_config": map[string]any{"log_fields": []string{"email"}, "algorithm": "sha256"}}} {
				w, _ = streamCall(t, e, "PATCH", id, bad)
				if w.Code != 400 {
					t.Fatalf("accepted invalid PATCH %v: %d %s", bad, w.Code, w.Body)
				}
			}
			w, out = streamCall(t, e, "PATCH", id, map[string]any{"filters": []any{map[string]any{"type": "category", "name": "auth.login.success"}}, "pii_config": map[string]any{"log_fields": []string{"email"}}, "isPriority": true})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			pii := out.(map[string]any)["pii_config"].(map[string]any)
			if pii["method"] != "mask" || pii["algorithm"] != "xxhash" {
				t.Fatal(pii)
			}
			w, _ = streamCall(t, e, "DELETE", id, nil)
			if w.Code != 204 {
				t.Fatal(w.Code, w.Body)
			}
			w, _ = streamCall(t, e, "GET", id, nil)
			if w.Code != 404 {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}
func TestLogStreamSinkValidation(t *testing.T) {
	for _, schema := range logrules.Inventory().Sinks {
		for _, field := range schema.Fields {
			t.Run(schema.Type+"/"+field.Name, func(t *testing.T) {
				e := newClientsEnv(t)
				logSetup(e)
				invalid := []any{nil, 42, map[string]any{"value": "x"}}
				if field.Type == "string" {
					invalid = append(invalid, true, []any{})
				}
				if field.Type == "boolean" {
					invalid = append(invalid, "true")
				}
				if field.Secret {
					invalid = append(invalid, logrules.Marker)
				}
				if len(field.Values) > 0 {
					invalid = append(invalid, "invalid-region-or-format")
				}
				if field.Pattern != "" {
					invalid = append(invalid, ":")
				}
				if field.Type == "array" {
					invalid = append(invalid, []any{map[string]any{"header": "x"}}, []any{map[string]any{"header": "x", "value": "y", "extra": "z"}}, []any{map[string]any{"header": "x\r\nInjected", "value": "y"}})
				}
				for _, bad := range invalid {
					sink := streamSink(schema.Type)
					sink[field.Name] = bad
					w, _ := streamCall(t, e, "POST", "", map[string]any{"type": schema.Type, "sink": sink})
					if w.Code != 400 {
						t.Fatalf("accepted %s=%v: %d %s", field.Name, bad, w.Code, w.Body)
					}
				}
				if field.Required {
					sink := streamSink(schema.Type)
					delete(sink, field.Name)
					w, _ := streamCall(t, e, "POST", "", map[string]any{"type": schema.Type, "sink": sink})
					if w.Code != 400 {
						t.Fatal("accepted missing required", field.Name, w.Code, w.Body)
					}
				}
			})
		}
	}
	e := newClientsEnv(t)
	logSetup(e)
	for _, body := range []string{`null`, `[]`, `{"type":"http","sink":null}`, `{"type":"unknown","sink":{}}`, `{"type":"http","sink":{"httpEndpoint":"https://ok.example"},"status":"active"}`, `{"type":"http","sink":{"httpEndpoint":"http://collector.example.test"}}`, `{"type":"http","sink":{"httpEndpoint":"https://user:pass@collector.example.test"}}`, `{"type":"http","sink":{"httpEndpoint":"https://collector.example.test/#fragment"}}`, `{"type":"http","sink":{"httpEndpoint":"https:///missing-host"}}`} {
		w, _ := streamCall(t, e, "POST", "", body)
		if w.Code != 400 {
			t.Fatal(body, w.Code, w.Body)
		}
	}
}
func TestLogStreamStartFrom(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	base := time.Now().UTC().Add(-time.Hour)
	events := []store.LogEvent{{TenantID: e.tn.ID, Type: "s", Date: base.Add(time.Hour)}, {TenantID: e.tn.ID, Type: "s", Date: base}, {TenantID: e.tn.ID, Type: "s", Date: base.Add(2 * time.Hour)}}
	if err := e.st.Logs().AppendLogs(t.Context(), events, nil); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := e.st.Logs().SearchLogs(t.Context(), e.tn.ID, nil, store.LogPage{PerPage: 10})
	var first, last int64
	for _, v := range rows {
		if first == 0 || v.Seq < first {
			first = v.Seq
		}
		if v.Seq > last {
			last = v.Seq
		}
	}
	for _, tc := range []struct {
		name  string
		extra map[string]any
		want  int64
	}{{"default", nil, last}, {"timestamp", map[string]any{"startFrom": base.Add(30 * time.Minute).Format(time.RFC3339Nano)}, first - 1}, {"future", map[string]any{"startFrom": base.Add(3 * time.Hour).Format(time.RFC3339Nano)}, last}} {
		t.Run(tc.name, func(t *testing.T) {
			id := streamCreate(t, e, "http", tc.extra)
			s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
			if s.Checkpoint != tc.want {
				t.Fatalf("checkpoint %d want%d", s.Checkpoint, tc.want)
			}
			if tc.name != "default" && s.StartFrom.IsZero() {
				t.Fatal("StartFrom not persisted")
			}
		})
	}
	for _, v := range []any{store.FormatLogID(first), "yesterday", nil, 123} {
		w, _ := streamCall(t, e, "POST", "", map[string]any{"type": "http", "sink": streamSink("http"), "startFrom": v})
		if w.Code != 400 {
			t.Fatal(v, w.Code, w.Body)
		}
	}
}
func TestCloudStreamsSuspended(t *testing.T) {
	for _, typ := range []string{"eventbridge", "eventgrid"} {
		t.Run(typ, func(t *testing.T) {
			e := newClientsEnv(t)
			logSetup(e)
			id := streamCreate(t, e, typ, nil)
			for _, status := range []string{"active", "paused"} {
				w, _ := streamCall(t, e, "PATCH", id, map[string]any{"status": status})
				if w.Code != 400 {
					t.Fatal(status, w.Code, w.Body)
				}
			}
			s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
			if s.Status != "suspended" {
				t.Fatal(s.Status)
			}
		})
	}
}
func TestLogStreamCrossTenant(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	id := streamCreate(t, e, "http", nil)
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		body := any(nil)
		if method == "PATCH" {
			body = map[string]any{"name": "stolen"}
		}
		w, _ := e.call(t, e.sys, m2mCaller(), method, "/api/v2/log-streams/"+id, body, streamHandler(t, e, method, id))
		if w.Code != 404 {
			t.Fatal(method, w.Code, w.Body)
		}
	}
	w, out := e.call(t, e.sys, m2mCaller(), "GET", "/api/v2/log-streams", nil, streamHandler(t, e, "GET", ""))
	if w.Code != 200 || len(out.([]any)) != 0 {
		t.Fatal(w.Code, w.Body)
	}
	s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if _, err := keys.OpenBound(e.w, "log-stream/v1", []string{e.sys.ID, id, s.Type}, s.SealedSecrets); err == nil {
		t.Fatal("cross tenant secret opened")
	}
	if _, err := keys.OpenBound(e.w, "log-stream/v1", []string{e.tn.ID, "other", s.Type}, s.SealedSecrets); err == nil {
		t.Fatal("cross resource secret opened")
	}
}
func TestLogStreamSecretNotInSapi(t *testing.T) {
	for _, typ := range []string{"http", "sumo", "mixpanel"} {
		t.Run(typ, func(t *testing.T) {
			e := newClientsEnv(t)
			c := logSetup(e)
			id := streamCreate(t, e, typ, nil)
			raw := eventJSON(t, onlyEvent(t, c, "sapi"))
			if strings.Contains(raw, "SENTINEL_") || !strings.Contains(raw, logrules.Marker) {
				t.Fatal(raw)
			}
			c.events = nil
			w, _ := streamCall(t, e, "PATCH", id, map[string]any{"sink": streamSink(typ)})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			raw = eventJSON(t, onlyEvent(t, c, "sapi"))
			if strings.Contains(raw, "SENTINEL_") {
				t.Fatal(raw)
			}
		})
	}
}

type conflictStreamStore struct {
	store.Store
	repo *conflictStreamRepo
}

func (s conflictStreamStore) Logs() store.Logs { return s.repo }

type conflictStreamRepo struct {
	store.Logs
	writes int
}

func (r *conflictStreamRepo) UpdateLogStream(context.Context, *store.LogStream, int) error {
	r.writes++
	return store.ErrConflict
}
func TestLogStreamPatchAtomicAndVersionRace(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	id := streamCreate(t, e, "http", nil)
	before, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	w, _ := streamCall(t, e, "PATCH", id, map[string]any{"name": "changed", "sink": map[string]any{"httpAuthorization": "replacement", "unknown": true}})
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	after, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid PATCH partially applied")
	}
	repo := &conflictStreamRepo{Logs: e.st.Logs()}
	e.h.Store = conflictStreamStore{Store: e.st, repo: repo}
	w, _ = streamCall(t, e, "PATCH", id, map[string]any{"name": "conflicted"})
	if w.Code != 409 || repo.writes != 3 {
		t.Fatal(w.Code, w.Body, repo.writes)
	}
	after, _ = e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("conflicted PATCH partially applied")
	}
}

type unavailableStreamStore struct{ store.Store }

func (s unavailableStreamStore) CheckLogsSupport(context.Context) error {
	return store.ErrLogsUnavailable
}
func (s unavailableStreamStore) Logs() store.Logs { return store.UnimplementedLogs{} }
func TestLogStreamUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	e.h.Store = unavailableStreamStore{e.st}
	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		id := "id"
		if method == "POST" {
			id = ""
		}
		w, _ := streamCall(t, e, method, id, map[string]any{"type": "http", "sink": streamSink("http")})
		if w.Code != 501 || !strings.Contains(w.Body.String(), "logs_unavailable") {
			t.Fatal(method, w.Code, w.Body)
		}
	}
}
func TestLogStreamResumeStoreState(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	id := streamCreate(t, e, "http", nil)
	s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	at := time.Now().UTC()
	leased, err := e.st.Logs().LeaseLogStream(t.Context(), "old-acquisition", at, at.Add(time.Minute))
	if err != nil || leased.ID != id {
		t.Fatal(leased, err)
	}
	err = e.st.Logs().RecordDelivery(t.Context(), e.tn.ID, id, "old-acquisition", store.LogStreamDelivery{Status: "suspended", Failures: 8, FailingSince: at.Add(-time.Hour), NextAt: at.Add(time.Hour), LastErrorClass: "transport", Checkpoint: s.Checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := streamCall(t, e, "PATCH", id, map[string]any{"status": "active"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	after, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if after.Status != "active" || after.Checkpoint != s.Checkpoint || after.Failures != 0 || !after.FailingSince.IsZero() || after.LeaseOwner != "" || after.LastErrorClass != "" || after.NextAt.After(time.Now().Add(time.Second)) {
		t.Fatal(after)
	}
	if err := e.st.Logs().RecordDelivery(t.Context(), e.tn.ID, id, "old-acquisition", store.LogStreamDelivery{}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatal("lease fencing", err)
	}
}

func TestLogStreamSecretReplacementAndUnconfiguredMarker(t *testing.T) {
	for _, schema := range logrules.Inventory().Sinks {
		for _, f := range schema.Fields {
			if !f.Secret {
				continue
			}
			t.Run(schema.Type+"/"+f.Name, func(t *testing.T) {
				e := newClientsEnv(t)
				logSetup(e)
				id := streamCreate(t, e, schema.Type, nil)
				replacement := any("REPLACEMENT_stream_secret")
				if f.Name == "sumoSourceAddress" {
					replacement = "https://collector.example.test/REPLACEMENT_stream_secret"
				}
				if f.Type == "array" {
					replacement = []any{map[string]any{"header": "X-Next", "value": "REPLACEMENT_stream_secret"}}
				}
				w, _ := streamCall(t, e, "PATCH", id, map[string]any{"sink": map[string]any{f.Name: replacement}})
				if w.Code != 200 || strings.Contains(w.Body.String(), "REPLACEMENT_") {
					t.Fatal(w.Code, w.Body)
				}
				s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
				if !reflect.DeepEqual(streamSecrets(t, e, s)[f.Name], replacement) {
					t.Fatal("replacement not persisted")
				}
			})
		}
	}
	e := newClientsEnv(t)
	logSetup(e)
	w, out := streamCall(t, e, "POST", "", map[string]any{"type": "http", "sink": map[string]any{"httpEndpoint": "https://collector.example.test"}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	id := out.(map[string]any)["id"].(string)
	for _, key := range []string{"httpAuthorization", "httpCustomHeaders"} {
		w, _ = streamCall(t, e, "PATCH", id, map[string]any{"sink": map[string]any{key: logrules.Marker}})
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
}
func TestLogStreamNestedAndNullableValidation(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	id := streamCreate(t, e, "http", nil)
	for _, body := range []string{`{"name":null}`, `{"name":false}`, `{"isPriority":"true"}`, `{"isPriority":null}`, `{"status":null}`, `{"status":"deleted"}`, `{"filters":null}`, `{"filters":[null]}`, `{"filters":[{"type":"category","name":"auth.login.success","extra":true}]}`, `{"filters":[{"type":"category","name":null}]}`, `{"pii_config":null}`, `{"pii_config":{}}`, `{"pii_config":{"log_fields":[]}}`, `{"pii_config":{"log_fields":["email","email"]}}`, `{"pii_config":{"log_fields":["email"],"method":null}}`, `{"pii_config":{"log_fields":["email"],"extra":true}}`, `{"sink":{"httpCustomHeaders":[{"header":"X-Key","value":"x\r\nInjected: bad"}]}}`, `{"sink":{"httpAuthorization":"x\nInjected: bad"}}`, `{"sink":{"datadogApiKey":"cross-type"}}`} {
		w, _ := streamCall(t, e, "PATCH", id, body)
		if w.Code != 400 {
			t.Fatal(body, w.Code, w.Body)
		}
	}
}

type refreshStreamStore struct {
	store.Store
	repo *refreshStreamRepo
}

func (s refreshStreamStore) Logs() store.Logs { return s.repo }

type refreshStreamRepo struct {
	store.Logs
	writes int
}

func (r *refreshStreamRepo) UpdateLogStream(ctx context.Context, s *store.LogStream, version int) error {
	r.writes++
	if r.writes == 1 {
		concurrent, err := r.Logs.GetLogStream(ctx, s.TenantID, s.ID)
		if err != nil {
			return err
		}
		concurrent.Sink["httpEndpoint"] = "https://new-collector.example.test/logs"
		if err = r.Logs.UpdateLogStream(ctx, concurrent, concurrent.Version); err != nil {
			return err
		}
		return store.ErrConflict
	}
	return r.Logs.UpdateLogStream(ctx, s, version)
}
func TestLogStreamPatchRefreshesConcurrentState(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	id := streamCreate(t, e, "http", nil)
	repo := &refreshStreamRepo{Logs: e.st.Logs()}
	e.h.Store = refreshStreamStore{Store: e.st, repo: repo}
	w, _ := streamCall(t, e, "PATCH", id, map[string]any{"name": "renamed after conflict"})
	if w.Code != 200 || repo.writes != 2 {
		t.Fatal(w.Code, w.Body, repo.writes)
	}
	s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if s.Name != "renamed after conflict" || s.Sink["httpEndpoint"] != "https://new-collector.example.test/logs" {
		t.Fatal("stale candidate overwrote concurrent change", s)
	}
}

func TestLogStreamStartFromZeroRejected(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	w, _ := streamCall(t, e, "POST", "", map[string]any{"type": "http", "sink": streamSink("http"), "startFrom": "0001-01-01T00:00:00Z"})
	if w.Code != 400 {
		t.Fatal("zero time must not silently mean latest", w.Code, w.Body)
	}
	id := streamCreate(t, e, "http", map[string]any{"startFrom": "0000-01-01T00:00:00Z"})
	s, _ := e.st.Logs().GetLogStream(t.Context(), e.tn.ID, id)
	if s.StartFrom.Year() != 0 || s.StartFrom.IsZero() {
		t.Fatal(s.StartFrom)
	}
}

func (s unavailableStreamStore) LogsSupported() bool { return false }

func TestLogStreamStartFromStrictRFC3339(t *testing.T) {
	e := newClientsEnv(t)
	logSetup(e)
	for _, value := range []string{"2026-10-31T00:00:00+24:00", "2026-10-31T00:00:00+00:60", "2026-10-31T00:00:00,123Z"} {
		w, _ := streamCall(t, e, "POST", "", map[string]any{"type": "http", "sink": streamSink("http"), "startFrom": value})
		if w.Code != 400 {
			t.Fatal("invalid RFC3339 accepted", value, w.Code, w.Body)
		}
	}
}
