package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errEventStreamInvalid = &Error{Status: 400, Code: "invalid_request", Message: "Invalid event stream configuration"}
var errEventsUnavailable = &Error{Status: 501, Code: "events_unavailable", Message: "The storage plugin does not support events"}
var eventStreamID = regexp.MustCompile(eventrules.StreamIDPattern)

func (h *Handlers) eventStreamError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrEventsUnavailable):
		Fail(w, errEventsUnavailable)
	case errors.Is(err, store.ErrInvalid):
		Fail(w, errEventStreamInvalid)
	case errors.Is(err, store.ErrConflict):
		Fail(w, &Error{Status: 409, Code: "conflict", Message: "Event stream conflict"})
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "not_found", Message: "Event stream not found"})
	default:
		var e *Error
		if errors.As(err, &e) {
			Fail(w, e)
		} else {
			Fail(w, internalError(h, r, "event streams", err))
		}
	}
}
func (h *Handlers) eventsRepo(w http.ResponseWriter, r *http.Request) (store.Events, bool) {
	if s, ok := h.Store.(store.EventsSupporter); ok {
		if err := s.CheckEventsSupport(r.Context()); err != nil {
			h.eventStreamError(w, r, err)
			return nil, false
		}
	}
	return h.Store.Events(), true
}
func eventStreamView(s *store.EventStream) map[string]any {
	subscriptions := make([]map[string]string, 0, len(s.Subscriptions))
	for _, typ := range s.Subscriptions {
		subscriptions = append(subscriptions, map[string]string{"event_type": typ})
	}
	// Project the frozen public destination fields. Sealed credentials and worker
	// internals can never enter the representation, even from a malformed row.
	cfg := map[string]any{}
	for _, path := range eventrules.Destination(s.DestType).PublicFields {
		switch path {
		case "webhook_authorization.method", "webhook_authorization.username", "webhook_authorization.header_key":
			auth, _ := s.Config["webhook_authorization"].(map[string]any)
			field := path[len("webhook_authorization."):]
			if v, ok := auth[field]; ok {
				public, _ := cfg["webhook_authorization"].(map[string]any)
				if public == nil {
					public = map[string]any{}
					cfg["webhook_authorization"] = public
				}
				public[field] = v
			}
		default:
			if v, ok := s.Config[path]; ok {
				cfg[path] = v
			}
		}
	}
	return map[string]any{"id": s.ID, "name": s.Name, "subscriptions": subscriptions, "destination": map[string]any{"type": s.DestType, "configuration": cfg}, "status": s.Status, "total_failures": s.TotalFailures, "created_at": s.CreatedAt, "updated_at": s.UpdatedAt}
}
func eventStreamQuery(r *http.Request, paging bool) (string, int, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", 0, store.ErrInvalid
	}
	take := eventrules.Limits.TakeDefault
	for k, v := range q {
		if !paging || (k != "from" && k != "take") || len(v) != 1 {
			return "", 0, store.ErrInvalid
		}
	}
	if q.Has("take") {
		take, err = strconv.Atoi(q.Get("take"))
		if err != nil || take < 1 || take > eventrules.Limits.TakeMax {
			return "", 0, store.ErrInvalid
		}
	}
	from := q.Get("from")
	if q.Has("from") && !eventStreamID.MatchString(from) {
		return "", 0, store.ErrInvalid
	}
	return from, take, nil
}
func (h *Handlers) ListEventStreams(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.eventsRepo(w, r)
	if !ok {
		return
	}
	from, take, err := eventStreamQuery(r, true)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	rows, next, err := repo.ListEventStreams(r.Context(), resolved(r).ID, from, take)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, eventStreamView(&rows[i]))
	}
	writeJSON(w, 200, map[string]any{"eventStreams": out, "next": next})
}
func (h *Handlers) GetEventStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.eventsRepo(w, r)
	if !ok {
		return
	}
	if _, _, err := eventStreamQuery(r, false); err != nil || !eventStreamID.MatchString(id) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	s, err := repo.GetEventStream(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	writeJSON(w, 200, eventStreamView(s))
}
func (h *Handlers) CreateEventStream(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.eventsRepo(w, r); !ok {
		return
	}
	if _, _, err := eventStreamQuery(r, false); err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	raw, err := decodeEventStreamObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var s *store.EventStream
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		limit := h.EventsConfig.MaxStreams
		if limit < 1 {
			limit = eventrules.Limits.MaxStreams
		}
		count, err := tx.Events().CountEventStreams(r.Context(), resolved(r).ID)
		if err != nil {
			return err
		}
		s = &store.EventStream{TenantID: resolved(r).ID, ID: "est_" + secrets.RandomString(22), Status: "enabled", Config: map[string]any{}, CreatedAt: h.now()}
		s.UpdatedAt = s.CreatedAt
		if err := h.applyEventStream(r, tx, s, raw, true); err != nil {
			return err
		}
		if count >= limit {
			return store.ErrConflict
		}
		s.Checkpoint, err = tx.Events().LatestEventSeq(r.Context(), s.TenantID)
		if err != nil {
			return err
		}
		return tx.Events().CreateEventStream(r.Context(), s)
	})
	if err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	logDetails(r, "create event stream", "id", s.ID, "type", s.DestType)
	writeJSON(w, 201, eventStreamView(s))
}
func (h *Handlers) UpdateEventStream(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.eventsRepo(w, r); !ok {
		return
	}
	if _, _, err := eventStreamQuery(r, false); err != nil || !eventStreamID.MatchString(id) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	raw, err := decodeEventStreamObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		var s *store.EventStream
		err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
			// Tenant reads lock the row within SQL transactions. Acquire it before
			// reading the stream/checkpoint so enabling cannot replay a concurrent
			// append that committed while the stream was disabled.
			if _, err := tx.Tenants().Get(r.Context(), resolved(r).ID); err != nil {
				return err
			}
			var err error
			s, err = tx.Events().GetEventStream(r.Context(), resolved(r).ID, id)
			if err != nil {
				return err
			}
			previous := s.Status
			if err := h.applyEventStream(r, tx, s, raw, false); err != nil {
				return err
			}
			if previous != "enabled" && s.Status == "enabled" {
				if s.TotalFailures >= eventrules.Limits.TotalFailures {
					return store.ErrInvalid
				}
				s.ConsecutiveFailures = 0
				s.Checkpoint, err = tx.Events().LatestEventSeq(r.Context(), s.TenantID)
				if err != nil {
					return err
				}
				s.LeaseOwner = ""
				s.LeaseUntil = time.Time{}
			}
			s.UpdatedAt = h.now()
			return tx.Events().UpdateEventStream(r.Context(), s, s.Version)
		})
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			h.eventStreamError(w, r, err)
			return
		}
		logDetails(r, "update event stream", "id", s.ID, "type", s.DestType)
		writeJSON(w, 200, eventStreamView(s))
		return
	}
	h.eventStreamError(w, r, store.ErrConflict)
}
func (h *Handlers) DeleteEventStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.eventsRepo(w, r)
	if !ok {
		return
	}
	if _, _, err := eventStreamQuery(r, false); err != nil || !eventStreamID.MatchString(id) {
		h.eventStreamError(w, r, store.ErrInvalid)
		return
	}
	if err := repo.DeleteEventStream(r.Context(), resolved(r).ID, id); err != nil {
		h.eventStreamError(w, r, err)
		return
	}
	logDetails(r, "delete event stream", "id", id)
	w.WriteHeader(204)
}
func (h *Handlers) applyEventStream(r *http.Request, tx store.Store, s *store.EventStream, raw map[string]json.RawMessage, create bool) error {
	private, err := eventstream.OpenSecrets(h.Wrapper, s)
	if err != nil {
		return err
	}
	if err = eventstream.Configure(s, raw, create, h.EventsConfig.AllowInsecureHTTP, private); err != nil {
		return err
	}
	if s.DestType == "action" {
		a, err := tx.Actions().GetAction(r.Context(), s.TenantID, s.Config["action_id"].(string))
		if errors.Is(err, store.ErrNotFound) || err == nil && a.Trigger != "event-stream" {
			return store.ErrInvalid
		}
		if err != nil {
			return err
		}
	}
	s.SealedSecret, err = eventstream.SealSecrets(h.Wrapper, s, private)
	return err
}

// Reject duplicate keys at every depth before map decoding can discard them.
// Keep the standard Management decoder for body limits and credential masking.
func decodeEventStreamObject(r *http.Request) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, errEventStreamInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return store.ErrInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return store.ErrInvalid
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return store.ErrInvalid
		}
		_, err = decoder.Token()
		return err
	}
	if value(0) != nil {
		return nil, errEventStreamInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errEventStreamInvalid
	}
	r.Body = &managementReplayBody{Reader: bytes.NewReader(data), original: r.Body}
	out, err := decodeObject(r)
	if err != nil {
		return nil, errEventStreamInvalid
	}
	return out, nil
}
