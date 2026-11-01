package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// EventDeliverer is the application's delivery worker, including its durable
// Actions runner and guarded webhook transport. Test deliveries persist nothing.
type EventDeliverer interface {
	Deliver(context.Context, *store.EventStream, []byte) []store.DeliveryAttempt
}

var deliveryEventID = regexp.MustCompile(eventrules.EventIDPattern)
var deliveryDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$`)

func parseDeliveryDate(s string) (time.Time, error) {
	if len(s) > 20 || !deliveryDate.MatchString(s) {
		return time.Time{}, store.ErrInvalid
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, store.ErrInvalid
	}
	return t.UTC(), nil
}
func deliveryFilter(raw map[string]json.RawMessage) (store.DeliveryFilter, error) {
	var f store.DeliveryFilter
	for k, v := range raw {
		switch k {
		case "statuses", "event_types":
			var list []string
			if string(v) == "null" || json.Unmarshal(v, &list) != nil {
				return f, store.ErrInvalid
			}
			for _, item := range list {
				if k == "statuses" {
					if item != "failed" {
						return f, store.ErrInvalid
					}
				} else if _, ok := eventrules.Lookup(item); !ok {
					return f, store.ErrInvalid
				}
			}
			if k == "statuses" {
				f.Statuses = list
			} else {
				f.EventTypes = list
			}
		case "date_from", "date_to":
			var s string
			if json.Unmarshal(v, &s) != nil {
				return f, store.ErrInvalid
			}
			t, err := parseDeliveryDate(s)
			if err != nil {
				return f, err
			}
			if k == "date_from" {
				f.From = t
			} else {
				f.To = t
			}
		default:
			return f, store.ErrInvalid
		}
	}
	if !f.From.IsZero() && !f.To.IsZero() && !f.From.Before(f.To) {
		return f, store.ErrInvalid
	}
	return f, nil
}
func deliveryQuery(r *http.Request) (store.DeliveryFilter, string, int, error) {
	var f store.DeliveryFilter
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return f, "", 0, store.ErrInvalid
	}
	raw := map[string]json.RawMessage{}
	take := eventrules.Limits.TakeDefault
	from := ""
	for k, values := range q {
		if len(values) != 1 {
			return f, "", 0, store.ErrInvalid
		}
		v := values[0]
		switch k {
		case "take":
			take, err = strconv.Atoi(v)
			if err != nil || take < 1 || take > eventrules.Limits.TakeMax {
				return f, "", 0, store.ErrInvalid
			}
		case "from":
			if !deliveryEventID.MatchString(v) {
				return f, "", 0, store.ErrInvalid
			}
			from = v
		case "statuses", "event_types":
			raw[k], _ = json.Marshal(strings.Split(v, ","))
		case "date_from", "date_to":
			raw[k], _ = json.Marshal(v)
		default:
			return f, "", 0, store.ErrInvalid
		}
	}
	f, err = deliveryFilter(raw)
	return f, from, take, err
}
func (h *Handlers) deliveryStream(w http.ResponseWriter, r *http.Request, id string, query bool) (store.Events, *store.EventStream, bool) {
	repo, ok := h.eventsRepo(w, r)
	if !ok {
		return nil, nil, false
	}
	if !eventStreamID.MatchString(id) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return nil, nil, false
	}
	if !query {
		if _, _, err := eventStreamQuery(r, false); err != nil {
			h.eventStreamError(w, r, err)
			return nil, nil, false
		}
	}
	s, err := repo.GetEventStream(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.eventStreamError(w, r, err)
		return nil, nil, false
	}
	return repo, s, true
}
func deliveryView(d *store.EventDelivery, body []byte) map[string]any {
	attempts := make([]map[string]any, 0, len(d.Attempts))
	for _, a := range d.Attempts {
		attempts = append(attempts, map[string]any{"status": a.Status, "timestamp": a.Timestamp.UTC(), "error_message": a.ErrorMessage, "duration": a.DurationMS})
	}
	return map[string]any{"id": d.EventID, "event_stream_id": d.StreamID, "status": d.Status, "event_type": d.EventType, "attempts": attempts, "event": json.RawMessage(body)}
}
func (h *Handlers) TestEventStream(w http.ResponseWriter, r *http.Request, id string) {
	_, s, ok := h.deliveryStream(w, r, id, false)
	if !ok {
		return
	}
	if s.Status != "enabled" {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	raw, err := decodeEventStreamObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for k := range raw {
		if k != "event_type" && k != "data" {
			h.eventStreamError(w, r, store.ErrInvalid)
			return
		}
	}
	var typ string
	if json.Unmarshal(raw["event_type"], &typ) != nil {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	rule, known := eventrules.Lookup(typ)
	if !known {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	// Catalog examples are documentation fixtures, not persisted tenant events.
	// The published deferred group examples use an ID outside their own alphabet.
	example := eventrules.Example(typ)
	if raw["data"] == nil && !rule.Emitted {
		example = []byte(strings.ReplaceAll(string(example), "grp_01949dad80fc7d56", "grp_123456789abcdefg"))
	}
	var envelope map[string]any
	if json.Unmarshal(example, &envelope) != nil {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	data, _ := envelope["data"].(map[string]any)
	if v, present := raw["data"]; present {
		data = nil
		if json.Unmarshal(v, &data) != nil || data == nil {
			h.eventStreamError(w, r, store.ErrInvalid)
			return
		}
	}
	// Synthetic tests follow the catalog data contract, which permits updates
	// without previous_object. Capture-time Build preconditions do not apply.
	at := h.now().UTC()
	eid := events.NewEventID()

	envelope["id"] = eid
	envelope["type"] = typ
	envelope["source"] = "urn:auth0:" + resolved(r).CanonicalHost
	envelope["time"] = at.Format("2006-01-02T15:04:05.000Z")
	envelope["a0tenant"] = s.TenantID
	envelope["data"] = data
	// Validate caller data before replacing tenant context; otherwise an unknown
	// nested tenant field could disappear before strict validation sees it.
	body, err := json.Marshal(envelope)
	if err != nil || eventrules.ValidateEvent(body) != nil {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	// Always identify the actual tenant, including when using a catalog fixture.
	c, ok := data["context"].(map[string]any)
	if !ok {
		c = map[string]any{}
		data["context"] = c
	}
	c["tenant"] = map[string]any{"id": s.TenantID}
	body, err = json.Marshal(envelope)
	if err != nil || eventrules.ValidateEvent(body) != nil {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	body = events.Stamp(body, id, true)
	if h.EventDeliverer == nil {
		h.eventStreamError(w, r, errors.New("event delivery worker unavailable"))
		return
	}
	attempts := h.EventDeliverer.Deliver(r.Context(), s, body)
	status := "failed"
	if len(attempts) > 0 && attempts[len(attempts)-1].Status == "success" {
		status = "success"
	}
	logDetails(r, "test event stream", "id", id, "event_type", typ)
	writeJSON(w, 202, deliveryView(&store.EventDelivery{EventID: eid, StreamID: id, EventType: typ, Status: status, Attempts: attempts}, body))
}
func (h *Handlers) ListDeliveries(w http.ResponseWriter, r *http.Request, id string) {
	repo, s, ok := h.deliveryStream(w, r, id, true)
	if !ok {
		return
	}
	f, from, take, err := deliveryQuery(r)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	rows, next, err := repo.ListDeliveries(r.Context(), s.TenantID, id, f, from, take)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		ev, err := repo.GetEvent(r.Context(), s.TenantID, rows[i].EventID)
		if err != nil {
			h.eventStreamError(w, r, err)
			return
		}
		out = append(out, deliveryView(&rows[i], events.Stamp(ev.Body, id, false)))
	}
	writeJSON(w, 200, map[string]any{"deliveries": out, "next": next})
}
func (h *Handlers) GetDelivery(w http.ResponseWriter, r *http.Request, id, eid string) {
	repo, s, ok := h.deliveryStream(w, r, id, false)
	if !ok {
		return
	}
	if !deliveryEventID.MatchString(eid) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	d, err := repo.GetDelivery(r.Context(), s.TenantID, id, eid)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	ev, err := repo.GetEvent(r.Context(), s.TenantID, eid)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	writeJSON(w, 200, deliveryView(d, events.Stamp(ev.Body, id, false)))
}
func (h *Handlers) redeliveryError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrPrecondition) {
		err = store.ErrConflict
	}
	h.eventStreamError(w, r, err)
}
func (h *Handlers) Redeliver(w http.ResponseWriter, r *http.Request, id string) {
	repo, s, ok := h.deliveryStream(w, r, id, false)
	if !ok {
		return
	}
	// An absent body means all failures. A present body must be a strict object.
	raw := map[string]json.RawMessage{}
	if r.Body != nil {
		var first [1]byte
		n, err := r.Body.Read(first[:])
		if err != nil && err != io.EOF {
			h.eventStreamError(w, r, store.ErrInvalid)
			return
		}
		if n > 0 {
			r.Body = &managementReplayBody{Reader: io.MultiReader(strings.NewReader(string(first[:n])), r.Body), original: r.Body}
			var decodeErr error
			raw, decodeErr = decodeEventStreamObject(r)
			if decodeErr != nil {
				Fail(w, decodeErr)
				return
			}
		}
	}
	f, err := deliveryFilter(raw)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	if _, err = repo.QueueRedelivery(r.Context(), s.TenantID, id, nil, &f); err != nil {
		h.redeliveryError(w, r, err)
		return
	}
	logDetails(r, "redeliver event stream", "id", id)
	writeJSON(w, 202, raw)
}
func (h *Handlers) RedeliverOne(w http.ResponseWriter, r *http.Request, id, eid string) {
	repo, s, ok := h.deliveryStream(w, r, id, false)
	if !ok {
		return
	}
	if !deliveryEventID.MatchString(eid) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	// Resolve event existence separately: unknown events are 404, known events
	// without a failed record are conflicts. QueueRedelivery atomically fences races.
	if _, err := repo.GetEvent(r.Context(), s.TenantID, eid); err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	if _, err := repo.QueueRedelivery(r.Context(), s.TenantID, id, []string{eid}, nil); err != nil {
		h.redeliveryError(w, r, err)
		return
	}
	logDetails(r, "redeliver event stream event", "id", id, "event_id", eid)
	w.WriteHeader(202)
}
