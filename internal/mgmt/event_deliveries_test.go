package mgmt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type deliveriesAPI interface {
	TestEventStream(http.ResponseWriter, *http.Request, string)
	ListDeliveries(http.ResponseWriter, *http.Request, string)
	GetDelivery(http.ResponseWriter, *http.Request, string, string)
	Redeliver(http.ResponseWriter, *http.Request, string)
	RedeliverOne(http.ResponseWriter, *http.Request, string, string)
}

func deliveryCall(t *testing.T, e *clientsEnv, tn *store.Tenant, op, id, eid, query string, body any) (*httptest.ResponseRecorder, any) {
	t.Helper()
	a, ok := any(e.h).(deliveriesAPI)
	if !ok {
		t.Fatal("delivery Management handlers are missing")
	}
	method := "POST"
	if op == "list" || op == "get" {
		method = "GET"
	}
	return e.call(t, tn, m2mCaller(), method, "/api/v2/event-streams/"+id+"/"+op+query, body, func(w http.ResponseWriter, r *http.Request) {
		switch op {
		case "test":
			a.TestEventStream(w, r, id)
		case "list":
			a.ListDeliveries(w, r, id)
		case "get":
			a.GetDelivery(w, r, id, eid)
		case "batch":
			a.Redeliver(w, r, id)
		case "one":
			a.RedeliverOne(w, r, id, eid)
		}
	})
}

type deliveryTransport func(*http.Request) (*http.Response, error)

func (f deliveryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func deliveryWorker(t *testing.T, e *clientsEnv, rt deliveryTransport) *eventstream.Worker {
	t.Helper()
	worker := eventstream.NewWorker(e.st, e.w, events.Config{}, &http.Client{Transport: rt}, nil, nil)
	e.h.EventDeliverer = worker
	return worker
}
func deliveryResponse(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("RECEIVER_SECRET")), Header: http.Header{}}
}
func seedDeliveries(t *testing.T, e *clientsEnv, id string, n int) []string {
	t.Helper()
	ids := []string{}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i := range n {
		ids = append(ids, fmt.Sprintf("evt_%022d", i+1))
		typ := "user.created"
		if i%2 == 1 {
			typ = "user.deleted"
		}
		ev, err := events.Build(t.Context(), e.tn, typ, map[string]any{"user_id": "auth0|sample"}, nil, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		ev.ID = ids[i]
		var body map[string]any
		json.Unmarshal(ev.Body, &body)
		body["id"] = ev.ID
		ev.Body, _ = json.Marshal(body)
		if err = e.st.Events().AppendEvents(t.Context(), []store.TenantEvent{ev}); err != nil {
			t.Fatal(err)
		}
		_, err = e.st.Events().LeaseEventStream(t.Context(), "seed", time.Now(), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err = e.st.Events().RecordEventDelivery(t.Context(), e.tn.ID, id, "seed", store.DeliveryOutcome{Checkpoint: ev.Seq, TotalFailures: i + 1, ConsecutiveFailures: i + 1, Failed: &store.EventDelivery{TenantID: e.tn.ID, StreamID: id, EventID: ev.ID, EventType: typ, Status: "failed", EventTime: ev.Time, Attempts: []store.DeliveryAttempt{{Status: "failed", Timestamp: now, ErrorMessage: "http_4xx: 404", DurationMS: 1.5}}}}); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	s.LeaseOwner = ""
	s.LeaseUntil = time.Time{}
	if err := e.st.Events().UpdateEventStream(t.Context(), s, s.Version); err != nil {
		t.Fatal(err)
	}
	return ids
}
func TestSendTestEvent(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Test", "webhook")
	var received []byte
	deliveryWorker(t, e, func(r *http.Request) (*http.Response, error) {
		received, _ = io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer EVENT_SECRET_SENTINEL" {
			t.Error("missing credentials")
		}
		return deliveryResponse(404), nil
	})
	before, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	for _, typ := range eventrules.Types() {
		t.Run(typ.Name, func(t *testing.T) {
			w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": typ.Name})
			if w.Code != 202 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			m := out.(map[string]any)
			if m["status"] != "failed" || m["event_type"] != typ.Name || len(m["attempts"].([]any)) != 1 {
				t.Fatal(m)
			}
			if err := eventrules.ValidateEvent(received); err != nil {
				t.Fatal(err)
			}
			var ev map[string]any
			json.Unmarshal(received, &ev)
			if ev["a0purpose"] != "test" || ev["a0tenant"] != e.tn.ID || ev["a0stream"] != id {
				t.Fatal(ev)
			}
			if strings.Contains(w.Body.String(), "SECRET") {
				t.Fatal(w.Body)
			}
		})
	}
	seq, _ := e.st.Events().LatestEventSeq(t.Context(), e.tn.ID)
	rows, _, _ := e.st.Events().ListDeliveries(t.Context(), e.tn.ID, id, store.DeliveryFilter{}, "", 100)
	after, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	if seq != 0 || len(rows) != 0 || !reflect.DeepEqual(before, after) {
		t.Fatal("test event persisted or changed stream")
	}
	for _, body := range []any{map[string]any{"event_type": "nope"}, map[string]any{"event_type": "user.created", "unknown": true}, `{"event_type":"user.created","event_type":"user.deleted"}`, map[string]any{"event_type": "user.created", "data": map[string]any{"object": map[string]any{"password_hash": "HASH_SECRET"}}}} {
		w, _ := deliveryCall(t, e, e.tn, "test", id, "", "", body)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	w, _ := eventStreamCall(t, e, "PATCH", id, map[string]any{"status": "disabled"})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w, _ = deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.created"})
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestDeliveriesFiltersAndPaging(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Failures", "webhook")
	ids := seedDeliveries(t, e, id, 3)
	for _, tc := range []struct {
		q string
		n int
	}{{"", 3}, {"?statuses=failed", 3}, {"?event_types=user.created", 2}, {"?event_types=user.created,user.deleted", 3}, {"?take=1", 1}, {"?take=100", 3}} {
		w, out := deliveryCall(t, e, e.tn, "list", id, "", tc.q, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if len(out.(map[string]any)["deliveries"].([]any)) != tc.n {
			t.Fatal(out)
		}
	}
	w, out := deliveryCall(t, e, e.tn, "list", id, "", "?take=1", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	next := out.(map[string]any)["next"].(string)
	w, out = deliveryCall(t, e, e.tn, "list", id, "", "?take=1&from="+next, nil)
	if w.Code != 200 || out.(map[string]any)["deliveries"].([]any)[0].(map[string]any)["id"] != ids[1] {
		t.Fatal(w.Code, w.Body)
	}
	for _, q := range []string{"?statuses=success", "?event_types=nope", "?take=101", "?take=0", "?unknown=a", "?take=1&take=2", "?statuses=failed&statuses=failed", "?from=bad", "?event_types="} {
		w, _ := deliveryCall(t, e, e.tn, "list", id, "", q, nil)
		if w.Code != 400 {
			t.Fatal(q, w.Code, w.Body)
		}
	}
	w, out = deliveryCall(t, e, e.tn, "get", id, ids[0], "", nil)
	if w.Code != 200 || out.(map[string]any)["event"] == nil {
		t.Fatal(w.Code, w.Body)
	}
	a := out.(map[string]any)["attempts"].([]any)[0].(map[string]any)
	if a["duration"] != 1.5 || !strings.HasSuffix(a["timestamp"].(string), "Z") {
		t.Fatal(a)
	}
}
func TestDeliveryDatePrecision(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Dates", "webhook")
	seedDeliveries(t, e, id, 3)
	d, _ := e.st.Events().GetDelivery(t.Context(), e.tn.ID, id, "evt_0000000000000000000001")
	from := d.EventTime.Format(time.RFC3339)
	to := d.EventTime.Add(time.Second).Format(time.RFC3339)
	w, out := deliveryCall(t, e, e.tn, "list", id, "", "?date_from="+url.QueryEscape(from)+"&date_to="+url.QueryEscape(to), nil)
	if w.Code != 200 || len(out.(map[string]any)["deliveries"].([]any)) != 1 {
		t.Fatal(w.Code, w.Body)
	}
	for _, date := range []string{"2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00,0Z", "bad"} {
		for _, op := range []string{"list", "batch"} {
			q := ""
			var b any = map[string]any{"date_from": date}
			if op == "list" {
				q = "?date_from=" + url.QueryEscape(date)
				b = nil
			}
			w, _ := deliveryCall(t, e, e.tn, op, id, "", q, b)
			if w.Code != 400 {
				t.Fatal(date, op, w.Code, w.Body)
			}
		}
	}
	w, _ = deliveryCall(t, e, e.tn, "list", id, "", "?date_from="+url.QueryEscape(to)+"&date_to="+url.QueryEscape(from), nil)
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestRedeliverConflicts(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Queue", "webhook")
	ids := seedDeliveries(t, e, id, 2)
	for _, tc := range []struct {
		op, eid string
		body    any
		code    int
	}{{"one", "evt_9999999999999999999999", nil, 404}, {"batch", "", map[string]any{"event_types": []string{"connection.created"}}, 409}, {"one", ids[0], nil, 202}, {"one", ids[0], nil, 409}, {"batch", "", nil, 409}} {
		w, _ := deliveryCall(t, e, e.tn, tc.op, id, tc.eid, "", tc.body)
		if w.Code != tc.code {
			t.Fatal(tc.op, w.Code, w.Body)
		}
	}
	d, _ := e.st.Events().GetDelivery(t.Context(), e.tn.ID, id, ids[1])
	if d.Queued {
		t.Fatal("conflicting batch partially queued")
	}
	ev, _ := events.Build(t.Context(), e.tn, "user.created", map[string]any{"user_id": "auth0|ok"}, nil, time.Now())
	e.st.Events().AppendEvents(t.Context(), []store.TenantEvent{ev})
	w, _ := deliveryCall(t, e, e.tn, "one", id, ev.ID, "", nil)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestRedeliverOneAndBatch(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			e := newClientsEnv(t)
			id := eventStreamCreate(t, e, "Recover", "webhook")
			ids := seedDeliveries(t, e, id, 2)
			if disabled {
				eventStreamCall(t, e, "PATCH", id, map[string]any{"status": "disabled"})
			}
			var sent atomic.Int32
			worker := deliveryWorker(t, e, func(r *http.Request) (*http.Response, error) {
				sent.Add(1)
				raw, _ := io.ReadAll(r.Body)
				if strings.Contains(string(raw), "a0purpose") {
					t.Error("test stamp on redelivery")
				}
				return deliveryResponse(204), nil
			})
			w, _ := deliveryCall(t, e, e.tn, "one", id, ids[0], "", nil)
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body)
			}
			body := map[string]any{"event_types": []string{"user.deleted"}, "statuses": []string{"failed"}}
			w, out := deliveryCall(t, e, e.tn, "batch", id, "", "", body)
			if w.Code != 202 || !reflect.DeepEqual(out, map[string]any{"event_types": []any{"user.deleted"}, "statuses": []any{"failed"}}) {
				t.Fatal(w.Code, w.Body)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); worker.Run(ctx) }()
			defer func() { cancel(); <-done }()
			deadline := time.After(5 * time.Second)
			for {
				rows, _, err := e.st.Events().ListDeliveries(t.Context(), e.tn.ID, id, store.DeliveryFilter{}, "", 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) == 0 {
					break
				}
				select {
				case <-deadline:
					t.Fatal("redelivery worker did not recover")
				case <-time.After(10 * time.Millisecond):
				}
			}
			s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
			if s.TotalFailures != 0 || sent.Load() != 2 {
				t.Fatal(s.TotalFailures, sent.Load())
			}
		})
	}
}
func TestDeliveriesCrossTenant(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Private", "webhook")
	ids := seedDeliveries(t, e, id, 1)
	for _, op := range []string{"test", "list", "get", "one", "batch"} {
		w, _ := deliveryCall(t, e, e.sys, op, id, ids[0], "", map[string]any{"event_type": "user.created"})
		if w.Code != 404 {
			t.Fatal(op, w.Code, w.Body)
		}
	}
	other := eventStreamCreate(t, e, "Other", "webhook")
	w, _ := deliveryCall(t, e, e.tn, "get", other, ids[0], "", nil)
	if w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestDeliveriesUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	for _, err := range []error{store.ErrEventsUnavailable, errors.New("temporary transport")} {
		e.h.Store = unavailableEventStore{e.st, err}
		for _, op := range []string{"test", "list", "get", "batch", "one"} {
			w, _ := deliveryCall(t, e, e.tn, op, "est_1234567890123456789012", "evt_1234567890123456789012", "", nil)
			want := 500
			if errors.Is(err, store.ErrEventsUnavailable) {
				want = 501
			}
			if w.Code != want {
				t.Fatal(op, w.Code, w.Body)
			}
		}
	}
	e.h.Store = e.st
	id := eventStreamCreate(t, e, "Recovered", "webhook")
	w, _ := deliveryCall(t, e, e.tn, "list", id, "", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestSendTestEventDataAndPrivacy(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Private test", "webhook")
	rec := logSetup(e)
	var output strings.Builder
	e.h.Log = slog.New(slog.NewTextHandler(&output, nil))
	var received []byte
	deliveryWorker(t, e, func(r *http.Request) (*http.Response, error) {
		received, _ = io.ReadAll(r.Body)
		return deliveryResponse(204), nil
	})
	var sample map[string]any
	if err := json.Unmarshal(eventrules.Example("user.updated"), &sample); err != nil {
		t.Fatal(err)
	}
	data := sample["data"].(map[string]any)
	data["object"].(map[string]any)["name"] = "Local supplied name"
	w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.updated", "data": data})
	if w.Code != 202 || out.(map[string]any)["status"] != "success" || !strings.Contains(string(received), "Local supplied name") {
		t.Fatal(w.Code, w.Body)
	}
	for _, path := range []string{"object", "previous_object", "identity", "profile", "context", "tenant"} {
		t.Run(path, func(t *testing.T) {
			var event map[string]any
			json.Unmarshal(eventrules.Example("user.updated"), &event)
			d := event["data"].(map[string]any)
			obj := d["object"].(map[string]any)
			switch path {
			case "object":
				obj["password_hash"] = "HASH_SECRET_SENTINEL"
			case "previous_object":
				d["previous_object"].(map[string]any)["password_hash"] = "HASH_SECRET_SENTINEL"
			case "identity":
				obj["identities"].([]any)[0].(map[string]any)["refresh_token"] = "TOKEN_SECRET_SENTINEL"
			case "profile":
				obj["identities"].([]any)[0].(map[string]any)["profileData"].(map[string]any)["access_token"] = "TOKEN_SECRET_SENTINEL"
			case "tenant":
				d["context"].(map[string]any)["tenant"].(map[string]any)["password"] = "HASH_SECRET_SENTINEL"
			case "context":
				d["context"].(map[string]any)["password"] = "HASH_SECRET_SENTINEL"
			}
			before := append([]byte(nil), received...)
			w, _ := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.updated", "data": d})
			if w.Code != 400 || !bytes.Equal(before, received) {
				t.Fatal("unsafe payload delivered", w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), "SECRET_SENTINEL") {
				t.Fatal(w.Body)
			}
		})
	}
	for _, ev := range rec.events {
		raw := eventJSON(t, ev)
		if strings.Contains(raw, "HASH_SECRET_SENTINEL") || strings.Contains(raw, "TOKEN_SECRET_SENTINEL") || strings.Contains(raw, "EVENT_SECRET_SENTINEL") {
			t.Fatal(raw)
		}
	}
	if strings.Contains(output.String(), "SECRET_SENTINEL") {
		t.Fatal(output.String())
	}
	// Invalid caller-supplied deferred IDs remain invalid; only default fixtures
	// are repaired, never the validator or caller input.
	json.Unmarshal(eventrules.Example("group.created"), &sample)
	w, _ = deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "group.created", "data": sample["data"]})
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestSendTestEventRetryAttempts(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Retries", "webhook")
	deliveryWorker(t, e, func(*http.Request) (*http.Response, error) { return deliveryResponse(503), nil })
	w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.created"})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	attempts := out.(map[string]any)["attempts"].([]any)
	if len(attempts) != 4 {
		t.Fatal(attempts)
	}
	for i, a := range attempts {
		m := a.(map[string]any)
		if m["error_message"] != "http_5xx: 503" || m["duration"].(float64) < 0 {
			t.Fatal(m)
		}
		if i > 0 {
			prev, _ := time.Parse(time.RFC3339Nano, attempts[i-1].(map[string]any)["timestamp"].(string))
			at, _ := time.Parse(time.RFC3339Nano, m["timestamp"].(string))
			if at.Sub(prev) < time.Duration(1<<(i-1))*time.Second {
				t.Fatal("retry too soon", i, at.Sub(prev))
			}
		}
	}
	rows, _, _ := e.st.Events().ListDeliveries(t.Context(), e.tn.ID, id, store.DeliveryFilter{}, "", 100)
	if len(rows) != 0 {
		t.Fatal("failed test persisted")
	}
}
func TestRedeliverFilterValidation(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Strict filters", "webhook")
	seedDeliveries(t, e, id, 1)
	for _, body := range []any{`{"unknown":1}`, `{"statuses":["success"]}`, `{"event_types":["nope"]}`, `{"statuses":null}`, `{"event_types":"user.created"}`, `{"date_from":"2026-01-02T00:00:00Z","date_to":"2026-01-01T00:00:00Z"}`, `{"statuses":["failed"],"statuses":[]}`, `null`, `[]`} {
		w, _ := deliveryCall(t, e, e.tn, "batch", id, "", "", body)
		if w.Code != 400 {
			t.Fatal(body, w.Code, w.Body)
		}
	}
	w, out := deliveryCall(t, e, e.tn, "batch", id, "", "", nil)
	if w.Code != 202 || len(out.(map[string]any)) != 0 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestSendTestEventResponseSchema(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Schema success", "webhook")
	deliveryWorker(t, e, func(*http.Request) (*http.Response, error) { return deliveryResponse(204), nil })
	w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.created"})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	doc, err := openapi3.NewLoader().LoadFromData(api.ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	schema := doc.Paths.Value("/api/v2/event-streams/{id}/test").Post.Responses.Status(202).Value.Content.Get("application/json").Schema.Value
	if err = schema.VisitJSON(out); err != nil {
		t.Fatal(err)
	}
	if err = doc.Components.Schemas["EventsEventStreamDeliveryStatusEnum"].Value.VisitJSON("success"); err == nil {
		t.Fatal("stored failures and filters must remain failed-only")
	}
}

func TestSendTestEventMinimalDataTenantContext(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Minimal data", "webhook")
	deliveryWorker(t, e, func(*http.Request) (*http.Response, error) { return deliveryResponse(204), nil })
	w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": "user.created", "data": map[string]any{"object": map[string]any{"user_id": "auth0|local", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "identities": []any{}}}})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	d := out.(map[string]any)["event"].(map[string]any)["data"].(map[string]any)
	c, ok := d["context"].(map[string]any)
	if !ok || c["tenant"].(map[string]any)["id"] != e.tn.ID {
		t.Fatal("missing tenant context", d)
	}
}
func TestDeliveryInvalidDateOffsets(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Offsets", "webhook")
	for _, date := range []string{"2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+00:60", "2026-01-01T00:00:00+01:00"} {
		w, _ := deliveryCall(t, e, e.tn, "list", id, "", "?date_from="+url.QueryEscape(date), nil)
		if w.Code != 400 {
			t.Fatal(date, w.Code, w.Body)
		}
	}
}
func TestDeliveriesDefaultPageSize(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Default page", "webhook")
	seedDeliveries(t, e, id, 52)
	w, out := deliveryCall(t, e, e.tn, "list", id, "", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	m := out.(map[string]any)
	if len(m["deliveries"].([]any)) != 50 || m["next"] != "evt_0000000000000000000050" {
		t.Fatal("wrong default page", len(m["deliveries"].([]any)), m["next"])
	}
}

func TestRedeliverReceiverFixedWhileDisabled(t *testing.T) {
	e := newClientsEnv(t)
	id := eventStreamCreate(t, e, "Live recovery", "webhook")
	var status atomic.Int32
	status.Store(404)
	worker := deliveryWorker(t, e, func(*http.Request) (*http.Response, error) { return deliveryResponse(int(status.Load())), nil })
	ids := []string{}
	for range 2 {
		ev, err := events.Build(t.Context(), e.tn, "user.created", map[string]any{"user_id": "auth0|local", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "identities": []any{}}, nil, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ev.ID)
		if err = e.st.Events().AppendEvents(t.Context(), []store.TenantEvent{ev}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	defer func() { cancel(); <-done }()
	wait := func(n int) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			rows, _, err := e.st.Events().ListDeliveries(t.Context(), e.tn.ID, id, store.DeliveryFilter{}, "", 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == n {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("wanted %d failures got %d", n, len(rows))
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait(2)
	w, _ := eventStreamCall(t, e, "PATCH", id, map[string]any{"status": "disabled"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	status.Store(204)
	w, _ = deliveryCall(t, e, e.tn, "one", id, ids[0], "", nil)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	wait(1)
	w, _ = deliveryCall(t, e, e.tn, "batch", id, "", "", nil)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	wait(0)
	s, _ := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
	if s.Status != "disabled" || s.TotalFailures != 0 {
		t.Fatal(s.Status, s.TotalFailures)
	}
}

// Synthetic tests obey the catalog's optional previous_object contract. Real
// capture keeps its stronger requirement for a prior update snapshot.
func TestSendTestEventUpdatedData(t *testing.T) {
	for _, tc := range []struct {
		typ    string
		object map[string]any
	}{
		{"user.updated", map[string]any{"user_id": "auth0|local", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "identities": []any{}}},
		{"organization.updated", map[string]any{"id": "org_1234567890abcdef"}},
		{"connection.updated", map[string]any{"id": "con_1234567890abcdef", "name": "local-oidc", "strategy": "oidc"}},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			e := newClientsEnv(t)
			id := eventStreamCreate(t, e, "Updated test", "webhook")
			before, err := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
			if err != nil {
				t.Fatal(err)
			}
			var received []byte
			deliveryWorker(t, e, func(r *http.Request) (*http.Response, error) {
				received, _ = io.ReadAll(r.Body)
				return deliveryResponse(204), nil
			})
			for _, withPrior := range []bool{false, true} {
				t.Run(fmt.Sprint(withPrior), func(t *testing.T) {
					data := map[string]any{"object": tc.object}
					var prior map[string]any
					if withPrior {
						prior = map[string]any{}
						for k, v := range tc.object {
							prior[k] = v
						}
						switch tc.typ {
						case "user.updated":
							prior["user_id"] = "auth0|prior"
						case "organization.updated":
							prior["id"] = "org_abcdef1234567890"
						case "connection.updated":
							prior["name"] = "previous-oidc"
						}
						data["previous_object"] = prior
					}
					fixture := map[string]any{"specversion": "1.0", "id": "evt_1234567890123456789012", "type": tc.typ, "source": "urn:auth0:fixture.example.test", "time": "2026-01-01T00:00:00Z", "a0tenant": "my-tenant", "data": data}
					raw, err := json.Marshal(fixture)
					if err != nil {
						t.Fatal(err)
					}
					if err = eventrules.ValidateEvent(raw); err != nil {
						t.Fatalf("invalid fixture: %v", err)
					}
					w, out := deliveryCall(t, e, e.tn, "test", id, "", "", map[string]any{"event_type": tc.typ, "data": data})
					if w.Code != 202 {
						t.Fatalf("valid updated test data: %d %s", w.Code, w.Body)
					}
					if out.(map[string]any)["status"] != "success" {
						t.Fatal(out)
					}
					if err = eventrules.ValidateEvent(received); err != nil {
						t.Fatal(err)
					}
					var sent map[string]any
					if err = json.Unmarshal(received, &sent); err != nil {
						t.Fatal(err)
					}
					if sent["a0purpose"] != "test" || sent["a0tenant"] != e.tn.ID || sent["a0stream"] != id {
						t.Fatal(sent)
					}
					sentData := sent["data"].(map[string]any)
					if !reflect.DeepEqual(sentData["object"], tc.object) {
						t.Fatal("supplied object changed", sentData)
					}
					if withPrior {
						if !reflect.DeepEqual(sentData["previous_object"], prior) {
							t.Fatal("supplied previous object changed", sentData)
						}
					} else if _, exists := sentData["previous_object"]; exists {
						t.Fatal("invented previous object", sentData)
					}
					if sentData["context"].(map[string]any)["tenant"].(map[string]any)["id"] != e.tn.ID {
						t.Fatal(sentData)
					}
				})
			}
			t.Run("unknown nested field", func(t *testing.T) {
				body := map[string]any{"event_type": tc.typ, "data": map[string]any{"object": tc.object, "context": map[string]any{"tenant": map[string]any{"id": "my-tenant", "password": "NESTED_SECRET_SENTINEL"}}}}
				prior := append([]byte(nil), received...)
				w, _ := deliveryCall(t, e, e.tn, "test", id, "", "", body)
				if w.Code != 400 || !bytes.Equal(prior, received) {
					t.Fatal("unknown nested data sent", w.Code, w.Body)
				}
			})
			seq, err := e.st.Events().LatestEventSeq(t.Context(), e.tn.ID)
			if err != nil {
				t.Fatal(err)
			}
			rows, _, err := e.st.Events().ListDeliveries(t.Context(), e.tn.ID, id, store.DeliveryFilter{}, "", 100)
			if err != nil {
				t.Fatal(err)
			}
			after, err := e.st.Events().GetEventStream(t.Context(), e.tn.ID, id)
			if err != nil {
				t.Fatal(err)
			}
			if seq != 0 || len(rows) != 0 || !reflect.DeepEqual(before, after) {
				t.Fatal("test persisted or changed stream")
			}
		})
	}
}
