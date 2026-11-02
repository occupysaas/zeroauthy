package mgmt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errSSEExpired = &Error{Status: 410, Code: "cursor_expired", Message: "Cursor points to data no longer available in the stream."}
var errSSEInvalid = &Error{Status: 400, Code: "invalid_request", Message: "Invalid event stream query"}

type ssePosition struct {
	seq          int64
	explicit     bool
	timestamp    bool
	historyFloor int64 // preexisting purges accepted only by an initial timestamp read
	from         time.Time
	types        []string
}

func encodeEventOffset(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(seq, 10)))
}
func parseSSEPosition(r *http.Request) (ssePosition, error) {
	p := ssePosition{}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return p, errSSEInvalid
	}
	for k, v := range q {
		if k != "from" && k != "from_timestamp" && k != "event_type" || k != "event_type" && len(v) != 1 {
			return p, errSSEInvalid
		}
	}
	// The explicitly incompatible query pair stays invalid even when the header
	// supplies the effective cursor. A header alone takes priority over timestamp.
	if q.Has("from") && q.Has("from_timestamp") {
		return p, errSSEInvalid
	}
	for _, typ := range q["event_type"] {
		if _, ok := eventrules.Lookup(typ); !ok {
			return p, errSSEInvalid
		}
		p.types = append(p.types, typ)
	}
	raw := q.Get("from")
	p.explicit = q.Has("from")
	if header, ok := r.Header["Last-Event-Id"]; ok {
		if len(header) != 1 {
			return p, errSSEInvalid
		}
		raw = header[0]
		p.explicit = true
	}
	if p.explicit {
		if len(raw) == 0 || len(raw) > 1024 {
			return p, errSSEInvalid
		}
		b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
		if e != nil {
			return p, errSSEInvalid
		}
		p.seq, e = strconv.ParseInt(string(b), 10, 64)
		if e != nil || p.seq < 0 || encodeEventOffset(p.seq) != raw {
			return p, errSSEInvalid
		}
		return p, nil
	}
	if q.Has("from_timestamp") {
		raw = q.Get("from_timestamp")
		if len(raw) != 20 {
			return p, errSSEInvalid
		}
		p.from, err = time.Parse("2006-01-02T15:04:05Z", raw)
		if err != nil || p.from.Format("2006-01-02T15:04:05Z") != raw {
			return p, errSSEInvalid
		}
		p.explicit = true
		p.timestamp = true
	}
	return p, nil
}

// A snapshot holds the tenant's existing mutation lock only while reading a
// bounded page. Append commits and retention use that same lock on SQL; memory
// transactions likewise exclude writers. Never keep a transaction while writing
// to the client. Fetch unfiltered settled rows so a filtered checkpoint cannot
// pass over pending matching rows. Store commits are ordered per tenant.
func (h *Handlers) sseSnapshot(ctx context.Context, tid string, p *ssePosition, initial bool) (rows []store.TenantEvent, err error) {
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, e := tx.Tenants().Get(ctx, tid); e != nil {
			return e
		}
		repo := tx.Events()
		floor, e := repo.PurgedEventSeq(ctx, tid)
		if e != nil {
			return e
		}
		if initial && !p.explicit {
			p.seq, e = repo.LatestEventSeq(ctx, tid)
			p.seq = max(p.seq, floor)
			return e
		}
		if initial && p.timestamp {
			// Timestamp reads start in the retained history, including rows
			// below a known purge watermark when event times were out of order.
			p.historyFloor = floor
			oldest, err := repo.OldestEventSeq(ctx, tid)
			if err != nil {
				return err
			}
			if oldest > 0 {
				p.seq = oldest - 1
			} else {
				p.seq = floor
			}
		}
		if p.seq < floor && (!p.timestamp || floor > p.historyFloor) {
			return errSSEExpired
		}
		rows, e = repo.EventsAfter(ctx, tid, p.seq, nil, 100, h.now().Add(-2*time.Second))
		return e
	})
	return
}
func (h *Handlers) acquireSSE(tid string) bool {
	h.sseMu.Lock()
	defer h.sseMu.Unlock()
	limit := h.EventsConfig.MaxConnections
	if limit < 1 {
		limit = eventrules.Limits.MaxConnections
	}
	if h.sseConnections[tid] >= limit {
		return false
	}
	if h.sseConnections == nil {
		h.sseConnections = map[string]int{}
	}
	h.sseConnections[tid]++
	return true
}
func (h *Handlers) releaseSSE(tid string) {
	h.sseMu.Lock()
	defer h.sseMu.Unlock()
	h.sseConnections[tid]--
	if h.sseConnections[tid] == 0 {
		delete(h.sseConnections, tid)
	}
}
func sseErrorCode(err error) string {
	switch {
	case errors.Is(err, errSSEExpired):
		return "cursor_expired"
	case errors.Is(err, store.ErrInvalid):
		return "invalid_cursor"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "processing_error"
	}
}

// Store/plugin errors may include event bodies or credentials. Only fixed
// public classes cross this boundary, including into server diagnostics.
func ssePreflightError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEventsUnavailable):
		Fail(w, errEventsUnavailable)
	case errors.Is(err, store.ErrInvalid):
		Fail(w, errSSEInvalid)
	case errors.Is(err, errSSEExpired):
		Fail(w, errSSEExpired)
	case errors.Is(err, store.ErrNotFound):
		WriteError(w, 404, "not_found", "Not found")
	default:
		WriteError(w, 500, "internal_error", "Internal error")
	}
}

// SubscribeEvents serves the tenant-local Events API. Authentication and live
// operator grants run at the router boundary; the adapter enforces read:events.
func (h *Handlers) SubscribeEvents(w http.ResponseWriter, r *http.Request) {
	p, err := parseSSEPosition(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if supporter, ok := h.Store.(store.EventsSupporter); ok {
		if err := supporter.CheckEventsSupport(r.Context()); err != nil {
			ssePreflightError(w, err)
			return
		}
	}
	tid := resolved(r).ID
	if !h.acquireSSE(tid) {
		Fail(w, &Error{Status: 403, Code: "access_denied", Message: "Maximum concurrent event stream connections reached. Please close existing connections."})
		return
	}
	defer h.releaseSSE(tid)
	rows, err := h.sseSnapshot(r.Context(), tid, &p, true)
	if err != nil {
		ssePreflightError(w, err)
		return
	}
	rc := http.NewResponseController(w)
	if err = rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		ssePreflightError(w, err)
		return
	}

	started := h.now()
	transport := &sseTransport{controller: rc, started: started, realDeadline: time.Now().Add(sseCycle), now: h.now}
	if err = transport.prepare(); err != nil {
		ssePreflightError(w, err)
		return
	}
	streamCtx, polls, cleanup := h.sseLifetime(r.Context(), transport)
	defer cleanup()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(message string) error {
		if err := transport.prepare(); err != nil {
			return err
		}
		if _, e := fmt.Fprint(w, message); e != nil {
			return e
		}
		return rc.Flush()
	}
	terminal := func(err error) { _ = send("event: error\ndata: {\"code\":\"" + sseErrorCode(err) + "\"}\n\n") }
	if send(":connected\n\nretry: 2000\n\n") != nil {
		return
	}
	heartbeat, offset := started, started

	// Progress frames describe only rows already examined. Check between rows
	// as well as idle polls so sustained backlog cannot starve heartbeats.
	progress := func(now time.Time) error {
		if now.Sub(heartbeat) >= 15*time.Second {
			if err := send(": heartbeat\n\n"); err != nil {
				return err
			}
			heartbeat = now
		}
		if now.Sub(offset) >= 30*time.Second && (!p.timestamp || p.seq >= p.historyFloor) {
			raw := encodeEventOffset(p.seq)
			if err := send("event: offset-only\nid: " + raw + "\ndata: {\"offset\":\"" + raw + "\"}\n\n"); err != nil {
				return err
			}
			offset = now
		}
		return nil
	}
	for {
		if h.now().Sub(started) >= sseCycle {
			return
		}
		if err := progress(h.now()); err != nil {
			return
		}
		// Drain bounded snapshots. Time and cancellation remain checked even under
		// sustained backlog; a slow client never holds the append/purge lock.
		for _, e := range rows {
			if err := streamCtx.Err(); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					terminal(err)
				}
				return
			}
			if h.now().Sub(started) >= sseCycle {
				return
			}
			if err := progress(h.now()); err != nil {
				return
			}
			if e.Seq <= p.seq {
				terminal(store.ErrInvalid)
				return
			}
			if (len(p.types) == 0 || slices.Contains(p.types, e.Type)) && (!p.timestamp || !e.Time.Before(p.from)) {
				if _, ok := eventrules.Lookup(e.Type); !ok {
					terminal(store.ErrInvalid)
					return
				}
				var body map[string]json.RawMessage
				if json.Unmarshal(e.Body, &body) != nil || body == nil {
					terminal(errors.New("invalid event"))
					return
				}
				delete(body, "a0stream")
				delete(body, "a0purpose")
				data, e2 := json.Marshal(map[string]any{"offset": encodeEventOffset(e.Seq), "event": body})
				if e2 != nil {
					terminal(e2)
					return
				}
				if send("event: "+e.Type+"\nid: "+encodeEventOffset(e.Seq)+"\ndata: "+string(data)+"\n\n") != nil {
					return
				}
			}
			p.seq = e.Seq
		}
		if len(rows) == 100 {
			rows, err = h.sseSnapshot(streamCtx, tid, &p, false)
			if err != nil {
				terminal(err)
				return
			}
			continue
		}
		select {
		case <-streamCtx.Done():
			if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
				terminal(r.Context().Err())
			}
			return
		case <-polls:
			now := h.now()
			if now.Sub(started) >= sseCycle {
				return
			}
			rows, err = h.sseSnapshot(streamCtx, tid, &p, false)
			if err != nil {
				terminal(err)
				return
			}
		}
	}
}
