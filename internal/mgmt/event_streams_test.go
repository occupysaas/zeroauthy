package mgmt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type eventStreamAPI interface {
	ListEventStreams(http.ResponseWriter, *http.Request)
	CreateEventStream(http.ResponseWriter, *http.Request)
	GetEventStream(http.ResponseWriter, *http.Request, string)
	UpdateEventStream(http.ResponseWriter, *http.Request, string)
	DeleteEventStream(http.ResponseWriter, *http.Request, string)
}

func eventStreamHandler(t *testing.T, e *clientsEnv, method, id string) http.HandlerFunc {
	t.Helper()
	a, ok := any(e.h).(eventStreamAPI)
	if !ok {
		t.Fatal("Event stream Management handlers are missing")
	}
	switch method {
	case "POST":
		return a.CreateEventStream
	case "GET":
		if id == "" {
			return a.ListEventStreams
		}
		return func(w http.ResponseWriter, r *http.Request) { a.GetEventStream(w, r, id) }
	case "PATCH":
		return func(w http.ResponseWriter, r *http.Request) { a.UpdateEventStream(w, r, id) }
	case "DELETE":
		return func(w http.ResponseWriter, r *http.Request) { a.DeleteEventStream(w, r, id) }
	}
	panic(method)
}
func eventStreamCall(t *testing.T, e *clientsEnv, method, id string, body any) (*httptest.ResponseRecorder, any) {
	t.Helper()
	path := "/api/v2/event-streams"
	handlerID := id
	if strings.HasPrefix(id, "?") {
		handlerID = ""
		path += id
	} else if id != "" {
		path += "/" + id
	}
	return e.call(t, e.tn, m2mCaller(), method, path, body, eventStreamHandler(t, e, method, handlerID))
}
func eventStreamBody(name, typ string) map[string]any {
	cfg := map[string]any{}
	switch typ {
	case "webhook":
		cfg = map[string]any{"webhook_endpoint": "https://collector.example.test/events", "webhook_authorization": map[string]any{"method": "bearer", "token": "EVENT_SECRET_SENTINEL"}}
	case "eventbridge":
		cfg = map[string]any{"aws_account_id": "123456789012", "aws_region": "us-east-1"}
	case "action":
		cfg = map[string]any{"action_id": "act-event"}
	}
	return map[string]any{"name": name, "subscriptions": []any{map[string]any{"event_type": "user.created"}}, "destination": map[string]any{"type": typ, "configuration": cfg}}
}
func eventStreamCreate(t *testing.T, e *clientsEnv, name, typ string) string {
	t.Helper()
	w, out := eventStreamCall(t, e, "POST", "", eventStreamBody(name, typ))
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	return out.(map[string]any)["id"].(string)
}
func TestEventStreamCRUD(t *testing.T) {
	for _, typ := range []string{"webhook", "action", "eventbridge"} {
		t.Run(typ, func(t *testing.T) {
			e := newClientsEnv(t)
			e.h.Store = eventActionStore{Store: e.st, tid: e.tn.ID}
			id := eventStreamCreate(t, e, "Example", typ)
			if len(id) != 26 || !strings.HasPrefix(id, "est_") {
				t.Fatal(id)
			}
			for _, method := range []string{"GET", "PATCH"} {
				var body any
				if method == "PATCH" {
					body = map[string]any{"name": "Renamed"}
				}
				w, _ := eventStreamCall(t, e, method, id, body)
				if w.Code != 200 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
					t.Fatal(w.Code, w.Body)
				}
			}
			w, out := eventStreamCall(t, e, "GET", "", nil)
			if w.Code != 200 || len(out.(map[string]any)["eventStreams"].([]any)) != 1 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
				t.Fatal(w.Code, w.Body)
			}
			if typ == "webhook" {
				s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
				if len(s.SealedSecret) == 0 || strings.Contains(string(s.SealedSecret), "EVENT_SECRET") {
					t.Fatal("missing encryption")
				}
				raw, err := keys.OpenBound(e.w, "event-stream/v1", []string{e.tn.ID, id, typ}, s.SealedSecret)
				if err != nil || !strings.Contains(string(raw), "EVENT_SECRET") {
					t.Fatal("cannot open bound secret", err)
				}
				dest := eventStreamBody("x", typ)["destination"].(map[string]any)
				delete(dest["configuration"].(map[string]any)["webhook_authorization"].(map[string]any), "token")
				w, _ = eventStreamCall(t, e, "PATCH", id, map[string]any{"destination": dest})
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				s2, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
				raw2, err := keys.OpenBound(e.w, "event-stream/v1", []string{e.tn.ID, id, typ}, s2.SealedSecret)
				if err != nil || !bytes.Equal(raw, raw2) {
					t.Fatal("omitted secret lost")
				}
				dest["configuration"].(map[string]any)["webhook_authorization"] = map[string]any{"method": "basic", "username": "service"}
				w, _ = eventStreamCall(t, e, "PATCH", id, map[string]any{"destination": dest})
				if w.Code != 400 {
					t.Fatal(w.Code, w.Body)
				}
			}
			w, _ = eventStreamCall(t, e, "DELETE", id, nil)
			if w.Code != 204 {
				t.Fatal(w.Code, w.Body)
			}
			w, _ = eventStreamCall(t, e, "GET", id, nil)
			if w.Code != 404 {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
	t.Run("validation", func(t *testing.T) {
		e := newClientsEnv(t)
		for _, mutate := range []func(map[string]any){
			func(b map[string]any) { b["unknown"] = true }, func(b map[string]any) { b["name"] = "" }, func(b map[string]any) { b["name"] = strings.Repeat("a", 129) }, func(b map[string]any) { b["subscriptions"] = []any{} }, func(b map[string]any) { b["subscriptions"] = []any{map[string]any{"event_type": "no.such.event"}} }, func(b map[string]any) {
				b["subscriptions"] = []any{map[string]any{"event_type": "user.created", "unknown": true}}
			},
			func(b map[string]any) { b["destination"].(map[string]any)["unknown"] = true },
			func(b map[string]any) {
				b["destination"].(map[string]any)["configuration"].(map[string]any)["unknown"] = true
			},
			func(b map[string]any) {
				b["destination"].(map[string]any)["configuration"].(map[string]any)["webhook_authorization"].(map[string]any)["unknown"] = true
			},
		} {
			b := eventStreamBody("Bad", "webhook")
			mutate(b)
			w, _ := eventStreamCall(t, e, "POST", "", b)
			if w.Code != 400 {
				t.Fatalf("accepted bad body: %d %s", w.Code, w.Body)
			}
		}
		for _, endpoint := range []string{"http://collector.example.test", "https://user:EVENT_SECRET@collector.example.test", "https://", "https://collector.example.test/#secret", "https://collector.example.test:bad/"} {
			b := eventStreamBody("Bad", "webhook")
			b["destination"].(map[string]any)["configuration"].(map[string]any)["webhook_endpoint"] = endpoint
			w, _ := eventStreamCall(t, e, "POST", "", b)
			if w.Code != 400 {
				t.Fatalf("accepted endpoint %q: %d %s", endpoint, w.Code, w.Body)
			}
		}
		for _, auth := range []map[string]any{{"method": "bearer"}, {"method": "bearer", "token": "bad\r\nvalue"}, {"method": "custom_header", "header_key": "bad key", "header_value": "secret"}, {"method": "custom_header", "header_key": "Host", "header_value": "secret"}, {"method": "basic", "username": "a:b", "password": "secret"}, {"method": "basic", "username": "a", "password": ""}} {
			b := eventStreamBody("Bad", "webhook")
			b["destination"].(map[string]any)["configuration"].(map[string]any)["webhook_authorization"] = auth
			w, _ := eventStreamCall(t, e, "POST", "", b)
			if w.Code != 400 {
				t.Fatalf("accepted auth: %d %s", w.Code, w.Body)
			}
		}
		for _, query := range []string{"?take=101", "?take=0", "?take=no", "?take=1&take=2", "?unknown=yes", "?from=invalid", "?take="} {
			w, _ := eventStreamCall(t, e, "GET", query, nil)
			if w.Code != 400 {
				t.Fatal(query, w.Code, w.Body)
			}
		}
		a := eventStreamCreate(t, e, "A", "webhook")
		b := eventStreamCreate(t, e, "B", "webhook")
		w, out := eventStreamCall(t, e, "GET", "?take=1", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		page := out.(map[string]any)
		next := page["next"].(string)
		if next == "" {
			t.Fatal("missing cursor")
		}
		w, out = eventStreamCall(t, e, "GET", "?take=1&from="+url.QueryEscape(next), nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		last := out.(map[string]any)["eventStreams"].([]any)[0].(map[string]any)["id"].(string)
		if next == last || !(last == a || last == b) {
			t.Fatal("pagination repeats", next, last)
		}
	})
}
func TestEventStreamActionMustBeEventStreamTrigger(t *testing.T) {
	e := newClientsEnv(t)
	if err := e.st.Actions().CreateAction(t.Context(), &store.Action{TenantID: e.tn.ID, ID: "post-login", Name: "post login", Trigger: "post-login"}); err != nil {
		t.Fatal(err)
	}
	e.h.Store = eventActionStore{Store: e.st, tid: e.tn.ID}
	for _, id := range []string{"missing", "post-login", "event-stream"} {
		body := eventStreamBody(id, "action")
		body["destination"].(map[string]any)["configuration"].(map[string]any)["action_id"] = id
		w, _ := eventStreamCall(t, e, "POST", "", body)
		want := 400
		if id == "event-stream" {
			want = 201
		}
		if w.Code != want {
			t.Fatal(id, w.Code, w.Body)
		}
	}
}
func TestEventBridgeDisabled(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "AWS", "eventbridge")
	s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	if s.Status != "disabled" || s.Config["aws_partner_event_source"] == nil {
		t.Fatal(s)
	}
	for _, patch := range []any{map[string]any{"status": "enabled"}, map[string]any{"destination": eventStreamBody("AWS", "eventbridge")["destination"]}, map[string]any{"destination": eventStreamBody("AWS", "webhook")["destination"]}} {
		w, _ := eventStreamCall(t, e, "PATCH", id, patch)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
}
func TestEventStreamLimitsAndNames(t *testing.T) {
	e := newClientsEnv(t)
	eventStreamCreate(t, e, "same", "webhook")
	w, _ := eventStreamCall(t, e, "POST", "", eventStreamBody("same", "webhook"))
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	for i := 1; i < 10; i++ {
		eventStreamCreate(t, e, string(rune('a'+i)), "webhook")
	}
	w, _ = eventStreamCall(t, e, "POST", "", eventStreamBody("overflow", "webhook"))
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	bad := eventStreamBody("invalid", "webhook")
	bad["unknown"] = true
	w, _ = eventStreamCall(t, e, "POST", "", bad)
	if w.Code != 400 {
		t.Fatal("quota bypassed body validation", w.Code, w.Body)
	}
}
func TestEventStreamReenableRules(t *testing.T) {
	for _, failures := range []int{4999, 5000} {
		e := newClientsEnv(t)
		if err := e.st.Events().AppendEvents(t.Context(), []store.TenantEvent{{TenantID: e.tn.ID, ID: "old", Time: time.Now(), Body: []byte(`{}`)}}); err != nil {
			t.Fatal(err)
		}
		id := eventStreamCreate(t, e, "Resume", "webhook")
		s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
		if s.Checkpoint != 1 {
			t.Fatal(s.Checkpoint)
		}
		s.Status = "disabled"
		s.TotalFailures = failures
		s.ConsecutiveFailures = 8
		if err := e.st.Events().UpdateEventStream(t.Context(), s, s.Version); err != nil {
			t.Fatal(err)
		}
		if err := e.st.Events().AppendEvents(t.Context(), []store.TenantEvent{{TenantID: e.tn.ID, ID: "new", Time: time.Now(), Body: []byte(`{}`)}}); err != nil {
			t.Fatal(err)
		}
		w, _ := eventStreamCall(t, e, "PATCH", id, map[string]any{"status": "enabled"})
		want := 200
		if failures == 5000 {
			want = 400
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body)
		}
		s, _ = e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
		if failures < 5000 && (s.Checkpoint != 2 || s.ConsecutiveFailures != 0 || s.TotalFailures != failures) {
			t.Fatal(s)
		}
	}
}
func TestEventStreamCrossTenant(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Private", "webhook")
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		w, _ := e.call(t, e.sys, m2mCaller(), method, "/api/v2/event-streams/"+id, map[string]any{"name": "stolen"}, eventStreamHandler(t, e, method, id))
		if w.Code != 404 {
			t.Fatal(w.Code, w.Body)
		}
	}
}
func TestEventStreamSecretNotInLogs(t *testing.T) {
	e := newClientsEnv(t)
	rec := logSetup(e)
	var log bytes.Buffer
	e.h.Log = slog.New(slog.NewJSONHandler(&log, nil))
	eventStreamCreate(t, e, "Private", "webhook")
	raw := eventJSON(t, onlyEvent(t, rec, "sapi"))
	for _, out := range []string{raw, log.String()} {
		if strings.Contains(out, "EVENT_SECRET_SENTINEL") || !strings.Contains(out, "REDACTED") {
			t.Fatal(out)
		}
	}
}

type unavailableEventStore struct {
	store.Store
	err error
}

func (s unavailableEventStore) Events() store.Events                     { return store.UnimplementedEvents{} }
func (s unavailableEventStore) CheckEventsSupport(context.Context) error { return s.err }
func (s unavailableEventStore) EventsSupported() bool                    { return false }
func TestEventStreamsUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = unavailableEventStore{e.st, store.ErrEventsUnavailable}
	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		id := "est_1234567890123456789012"
		if method == "POST" {
			id = ""
		}
		w, _ := eventStreamCall(t, e, method, id, map[string]any{})
		if w.Code != 501 || !strings.Contains(w.Body.String(), "events_unavailable") {
			t.Fatal(w.Code, w.Body)
		}
	}
	e.h.Store = unavailableEventStore{e.st, errors.New("temporary transport")}
	w, _ := eventStreamCall(t, e, "GET", "", nil)
	if w.Code != 500 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestEventStreamAllWebhookMethods(t *testing.T) {
	for _, auth := range []map[string]any{{"method": "basic", "username": "service", "password": "EVENT_SECRET_SENTINEL"}, {"method": "bearer", "token": "EVENT_SECRET_SENTINEL"}, {"method": "custom_header", "header_key": "X-Key", "header_value": "EVENT_SECRET_SENTINEL"}} {
		e := newClientsEnv(t)
		b := eventStreamBody("Private", "webhook")
		b["destination"].(map[string]any)["configuration"].(map[string]any)["webhook_authorization"] = auth
		w, _ := eventStreamCall(t, e, "POST", "", b)
		if w.Code != 201 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
			t.Fatal(w.Code, w.Body)
		}
	}
}

// The event-stream trigger is intentionally activated in Task 8. This
// tenant-scoped Actions adapter supplies the prerequisite future Action only.
type eventActionStore struct {
	store.Store
	tid string
}

func (s eventActionStore) Actions() store.Actions { return eventActions{s.Store.Actions(), s.tid} }
func (s eventActionStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(eventActionStore{tx, s.tid}) })
}

type eventActions struct {
	store.Actions
	tid string
}

func (a eventActions) GetAction(ctx context.Context, tid, id string) (*store.Action, error) {
	if tid == a.tid && (id == "event-stream" || id == "act-event") {
		return &store.Action{TenantID: tid, ID: id, Name: "event", Trigger: "event-stream"}, nil
	}
	return a.Actions.GetAction(ctx, tid, id)
}

func TestEventStreamStrictJSON(t *testing.T) {
	e := newClientsEnv(t)
	for _, raw := range []string{
		`{"name":"One","name":"Two","subscriptions":[{"event_type":"user.created"}],"destination":{"type":"eventbridge","configuration":{"aws_account_id":"123456789012","aws_region":"us-east-1"}}}`,
		`{"name":"One","subscriptions":[{"event_type":"user.created"}],"destination":{"type":"webhook","configuration":{"webhook_endpoint":"https://collector.example.test/events","webhook_authorization":{"method":"bearer","token":"one","token":"two"}}}}`,
	} {
		w, _ := eventStreamCall(t, e, "POST", "", raw)
		if w.Code != 400 {
			t.Fatal("accepted ambiguous JSON", w.Code, w.Body)
		}
	}
}
func TestEventStreamPatchAtomicAndConflicts(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Original", "webhook")
	eventStreamCreate(t, e, "Taken", "webhook")
	before, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	for _, body := range []any{map[string]any{"name": "Changed", "status": "unknown"}, map[string]any{"total_failures": 0}, map[string]any{"name": "Taken"}} {
		w, _ := eventStreamCall(t, e, "PATCH", id, body)
		if w.Code != 400 && w.Code != 409 {
			t.Fatal(w.Code, w.Body)
		}
		after, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
		if after.Name != before.Name || after.Version != before.Version || !bytes.Equal(before.SealedSecret, after.SealedSecret) {
			t.Fatal("failed patch modified persisted stream")
		}
	}
}

func TestEventStreamFailureSummary(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Summary", "webhook")
	s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	s.TotalFailures = 42
	if err := e.st.Events().UpdateEventStream(t.Context(), s, s.Version); err != nil {
		t.Fatal(err)
	}
	w, out := eventStreamCall(t, e, "GET", id, nil)
	if w.Code != 200 || out.(map[string]any)["total_failures"] != float64(42) {
		t.Fatal(w.Code, w.Body)
	}
	w, out = eventStreamCall(t, e, "GET", "", nil)
	if w.Code != 200 || out.(map[string]any)["eventStreams"].([]any)[0].(map[string]any)["total_failures"] != float64(42) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestEventStreamDefaultAndMaximumPageSize(t *testing.T) {
	e := newClientsEnv(t)
	for i := 0; i < 101; i++ {
		if err := e.st.Events().CreateEventStream(t.Context(), &store.EventStream{TenantID: e.tn.ID, ID: fmt.Sprintf("est_%022d", i), Name: fmt.Sprint(i), Status: "disabled", DestType: "webhook", Config: map[string]any{}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		query string
		want  int
	}{{"", 50}, {"?take=100", 100}} {
		w, out := eventStreamCall(t, e, "GET", tc.query, nil)
		if w.Code != 200 || len(out.(map[string]any)["eventStreams"].([]any)) != tc.want {
			t.Fatal(w.Code, w.Body)
		}
	}
}

type transientEventStore struct {
	store.Store
	calls int
}

func (s *transientEventStore) CheckEventsSupport(context.Context) error {
	s.calls++
	if s.calls == 1 {
		return errors.New("temporary event transport")
	}
	return nil
}
func (s *transientEventStore) EventsSupported() bool { return false }
func TestEventStreamCapabilityRecovers(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = &transientEventStore{Store: e.st}
	for _, want := range []int{500, 200} {
		w, _ := eventStreamCall(t, e, "GET", "", nil)
		if w.Code != want {
			t.Fatal(w.Code, w.Body)
		}
	}
}

type conflictEventStore struct {
	store.Store
	tid, id          string
	injected, always bool
}
type conflictEventView struct{ store.Store }

func (s conflictEventView) Events() store.Events { return conflictEventRepo{s.Store.Events()} }

type conflictEventRepo struct{ store.Events }

func (conflictEventRepo) UpdateEventStream(context.Context, *store.EventStream, int) error {
	return store.ErrConflict
}
func (s *conflictEventStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	inject := s.always || !s.injected
	err := s.Store.WithTx(ctx, func(tx store.Store) error {
		if inject {
			return fn(conflictEventView{tx})
		}
		return fn(tx)
	})
	if !s.injected && errors.Is(err, store.ErrConflict) {
		s.injected = true
		if !s.always {
			stream, getErr := s.Store.Events().GetEventStream(ctx, s.tid, s.id)
			if getErr != nil {
				return getErr
			}
			stream.TotalFailures = 7
			stream.Subscriptions = []string{"user.updated"}
			if updateErr := s.Store.Events().UpdateEventStream(ctx, stream, stream.Version); updateErr != nil {
				return updateErr
			}
		}
	}
	return err
}
func TestEventStreamOptimisticUpdateRefreshesState(t *testing.T) {
	for _, always := range []bool{false, true} {
		e := newClientsEnv(t)
		id := eventStreamCreate(t, e, "Original", "webhook")
		e.h.Store = &conflictEventStore{Store: e.st, tid: e.tn.ID, id: id, always: always}
		w, _ := eventStreamCall(t, e, "PATCH", id, map[string]any{"name": "Renamed"})
		want := 200
		if always {
			want = 409
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body)
		}
		s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
		if always {
			if s.Name != "Original" || s.Version != 1 {
				t.Fatal("conflict patch persisted", s)
			}
		} else if s.Name != "Renamed" || s.TotalFailures != 7 || len(s.Subscriptions) != 1 || s.Subscriptions[0] != "user.updated" {
			t.Fatal("retry clobbered concurrent state", s)
		}
	}
}

func TestEventStreamWebhookMethodAndSecretReplacement(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Private", "webhook")
	for _, auth := range []map[string]any{{"method": "basic", "username": "service", "password": "EVENT_SECRET_REPLACEMENT"}, {"method": "custom_header", "header_key": "X-Events-Key", "header_value": "EVENT_SECRET_REPLACEMENT"}} {
		dest := eventStreamBody("unused", "webhook")["destination"].(map[string]any)
		dest["configuration"].(map[string]any)["webhook_authorization"] = auth
		w, _ := eventStreamCall(t, e, "PATCH", id, map[string]any{"destination": dest})
		if w.Code != 200 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
			t.Fatal(w.Code, w.Body)
		}
		s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
		raw, err := keys.OpenBound(e.w, "event-stream/v1", []string{e.tn.ID, id, "webhook"}, s.SealedSecret)
		if err != nil {
			t.Fatal(err)
		}
		var private map[string]any
		if err := json.Unmarshal(raw, &private); err != nil {
			t.Fatal(err)
		}
		key := "password"
		if auth["method"] == "custom_header" {
			key = "header_value"
		}
		if len(private) != 1 || private[key] != "EVENT_SECRET_REPLACEMENT" {
			t.Fatal("old authorization method credential retained")
		}
		public, err := json.Marshal(s.Config)
		if err != nil || strings.Contains(string(public), "EVENT_SECRET") {
			t.Fatal("plaintext persisted in public configuration")
		}
		for _, binding := range [][]string{{e.sys.ID, id, "webhook"}, {e.tn.ID, "est_other", "webhook"}, {e.tn.ID, id, "action"}} {
			if _, err := keys.OpenBound(e.w, "event-stream/v1", binding, s.SealedSecret); err == nil {
				t.Fatal("secret opened with different binding")
			}
		}
		delete(auth, key)
		w, _ = eventStreamCall(t, e, "PATCH", id, map[string]any{"destination": dest})
		if w.Code != 200 {
			t.Fatal("same-method omission rejected", w.Code, w.Body)
		}
	}
}

func TestEventStreamValidationErrorCodes(t *testing.T) {
	e := newClientsEnv(t)
	for _, tc := range []struct {
		method, id string
		body       any
	}{{"POST", "", map[string]any{}}, {"POST", "", `null`}, {"POST", "", `{`}, {"GET", "?take=101", nil}, {"GET", "?unknown=yes", nil}} {
		w, out := eventStreamCall(t, e, tc.method, tc.id, tc.body)
		if w.Code != 400 || out.(map[string]any)["errorCode"] != "invalid_request" {
			t.Fatal(w.Code, w.Body)
		}
	}
}

func TestEventStreamWebhookRoutingQuery(t *testing.T) {
	for _, endpoint := range []string{
		"https://collector.example.test/events?tenant=acme",
		"https://collector.example.test/events?format=cloudevents&tenant=acme",
		"https://collector.example.test/events?",
	} {
		t.Run(endpoint, func(t *testing.T) {
			e := newClientsEnv(t)
			body := eventStreamBody("Routing query", "webhook")
			destination := body["destination"].(map[string]any)
			config := destination["configuration"].(map[string]any)
			config["webhook_endpoint"] = endpoint
			w, out := eventStreamCall(t, e, "POST", "", body)
			if w.Code != 201 {
				t.Fatalf("create routing endpoint: %d %s", w.Code, w.Body)
			}
			id := out.(map[string]any)["id"].(string)
			check := func(w *httptest.ResponseRecorder, out any, wantEndpoint string) {
				t.Helper()
				public := out.(map[string]any)["destination"].(map[string]any)["configuration"].(map[string]any)
				auth := public["webhook_authorization"].(map[string]any)
				if public["webhook_endpoint"] != wantEndpoint || auth["method"] != "bearer" || len(auth) != 1 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
					t.Fatal("public endpoint or credential projection", w.Body)
				}
				saved, err := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
				if err != nil {
					t.Fatal(err)
				}
				if saved.Config["webhook_endpoint"] != wantEndpoint || len(saved.SealedSecret) == 0 {
					t.Fatal("endpoint not preserved with sealed credentials")
				}
				raw, err := keys.OpenBound(e.w, "event-stream/v1", []string{e.tn.ID, id, "webhook"}, saved.SealedSecret)
				if err != nil {
					t.Fatal(err)
				}
				var private map[string]any
				if json.Unmarshal(raw, &private) != nil || len(private) != 1 || private["token"] != "EVENT_SECRET_SENTINEL" {
					t.Fatal("authorization credential lost")
				}
			}
			check(w, out, endpoint)
			patchEndpoint := endpoint
			if strings.HasSuffix(endpoint, "?") {
				patchEndpoint = "https://collector.example.test/updated?"
			} else {
				patchEndpoint = strings.Replace(endpoint, "/events?", "/updated?", 1)
			}
			config["webhook_endpoint"] = patchEndpoint
			delete(config["webhook_authorization"].(map[string]any), "token")
			w, out = eventStreamCall(t, e, "PATCH", id, map[string]any{"destination": destination})
			if w.Code != 200 {
				t.Fatalf("patch routing endpoint: %d %s", w.Code, w.Body)
			}
			check(w, out, patchEndpoint)
		})
	}
}
