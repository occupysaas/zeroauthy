package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var logLimits = logrules.Inventory().Limits
var logProjectionFields = func() map[string]bool {
	fields := map[string]bool{}
	for _, f := range logrules.Inventory().LogFields {
		fields[f.Name] = true
	}
	return fields
}()

var errLogsUnavailable = &Error{Status: 501, Code: "logs_unavailable", Message: "The storage plugin does not support logs"}

func (h *Handlers) logError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrLogsUnavailable):
		Fail(w, errLogsUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "not_found", Message: "Log not found"})
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badQuery("Invalid log query"))
	default:
		var e *Error
		if errors.As(err, &e) {
			Fail(w, e)
		} else {
			Fail(w, internalError(h, r, "logs", err))
		}
	}
}
func (h *Handlers) logsRepo(w http.ResponseWriter, r *http.Request) (store.Logs, bool) {
	if p, ok := h.Store.(store.LogsSupporter); ok {
		if err := p.CheckLogsSupport(r.Context()); err != nil {
			h.logError(w, r, err)
			return nil, false
		}
	}
	return h.Store.Logs(), true
}
func logParams(r *http.Request, user bool) (store.LogPage, *store.LogQuery, []string, bool, error) {
	p := store.LogPage{PerPage: logLimits["per_page_default"]}
	q := r.URL.Query()
	include := true
	allowed := []string{"page", "per_page", "sort", "include_totals"}
	if !user {
		allowed = append(allowed, "q", "fields", "include_fields", "from", "take")
	}
	checkpoint := !user && (q.Has("from") || q.Has("take"))
	for k, v := range q {
		// Checkpoint reads ignore every other parameter, including unknown
		// names and repeated values. Only cursor/take validation applies.
		if checkpoint && k != "from" && k != "take" {
			continue
		}
		if !slices.Contains(allowed, k) || len(v) != 1 {
			return p, nil, nil, include, badQuery("Unsupported or repeated parameter %q", k)
		}
	}
	if !user && (q.Has("from") || q.Has("take")) {
		return p, nil, nil, include, nil
	}
	number := func(k string, def, lo, hi int) (int, error) {
		if !q.Has(k) {
			return def, nil
		}
		n, err := strconv.Atoi(q.Get(k))
		if err != nil || n < lo || n > hi {
			return 0, badQuery("Invalid %s", k)
		}
		return n, nil
	}
	var err error
	if p.PerPage, err = number("per_page", logLimits["per_page_default"], 1, logLimits["per_page_max"]); err != nil {
		return p, nil, nil, include, err
	}
	if p.Page, err = number("page", 0, 0, logLimits["page_results_max"]-1); err != nil {
		return p, nil, nil, include, err
	}
	if p.Page > logLimits["page_results_max"]/p.PerPage-1 {
		return p, nil, nil, include, badQuery("Pagination exceeds 1000 records")
	}
	switch q.Get("sort") {
	case "", "date:-1":
	case "date:1":
		p.Ascending = true
	default:
		return p, nil, nil, include, badQuery("Invalid sort")
	}
	if p.IncludeTotals, err = boolParam(r, "include_totals", false); err != nil {
		return p, nil, nil, include, err
	}
	if !user {
		if include, err = boolParam(r, "include_fields", true); err != nil {
			return p, nil, nil, include, err
		}
	}
	var fields []string
	if !user && q.Get("fields") != "" {
		for _, f := range strings.Split(q.Get("fields"), ",") {
			if !logProjectionFields[f] {
				return p, nil, nil, include, badQuery("Unknown log field")
			}
			fields = append(fields, f)
		}
	}
	var ast *store.LogQuery
	if !user {
		ast, err = logsearch.Parse(q.Get("q"))
		if err != nil {
			return p, nil, nil, include, badQuery("Invalid log search")
		}
	}
	return p, ast, fields, include, nil
}
func logView(r *http.Request, e store.LogEvent, fields []string, include bool) map[string]any {
	out := map[string]any{}
	d := json.NewDecoder(bytes.NewReader(e.Body))
	d.UseNumber()
	_ = d.Decode(&out)
	if out == nil {
		out = map[string]any{}
	}
	out["type"] = e.Type
	out["date"] = e.Date.UTC().Format(time.RFC3339Nano)
	out = logs.ScrubStoredEvent(r.Context(), out)
	// The server-assigned cursor is protocol metadata, independent of body masks.
	out["log_id"] = e.ID
	out["_id"] = e.ID
	if len(fields) > 0 {
		for k := range out {
			if slices.Contains(fields, k) != include {
				delete(out, k)
			}
		}
	}
	return out
}
func (h *Handlers) writeLogs(w http.ResponseWriter, r *http.Request, events []store.LogEvent, total int, p store.LogPage, fields []string, include, checkpoint bool) {
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		items = append(items, logView(r, e, fields, include))
	}
	if p.IncludeTotals && !checkpoint {
		writeJSON(w, 200, map[string]any{"logs": items, "start": p.Page * p.PerPage, "limit": p.PerPage, "length": len(items), "total": min(total, logLimits["page_results_max"])})
	} else {
		writeJSON(w, 200, items)
	}
}

// ListLogs reads a bounded page or settled sequence checkpoint.
func (h *Handlers) ListLogs(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	p, q, fields, include, err := logParams(r, false)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	v := r.URL.Query()
	if v.Has("from") || v.Has("take") {
		take := logLimits["take_default"]
		if v.Has("take") {
			take, err = strconv.Atoi(v.Get("take"))
			if err != nil || take < 1 || take > logLimits["take_max"] {
				Fail(w, badQuery("Invalid take"))
				return
			}
		}
		settled := h.now().Add(-time.Duration(logLimits["settle_seconds"]) * time.Second)
		var events []store.LogEvent
		if v.Has("from") {
			after, e := store.ParseLogID(v.Get("from"))
			if e != nil {
				Fail(w, badQuery("Invalid from"))
				return
			}
			events, err = repo.LogsAfter(r.Context(), resolved(r).ID, after, nil, take, settled)
		} else {
			events, err = repo.LatestLogs(r.Context(), resolved(r).ID, nil, take, settled)
		}
		if err != nil {
			h.logError(w, r, err)
			return
		}
		h.writeLogs(w, r, events, 0, p, nil, true, true)
		return
	}
	events, total, err := repo.SearchLogs(r.Context(), resolved(r).ID, q, p)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	h.writeLogs(w, r, events, total, p, fields, include, false)
}
func (h *Handlers) GetLog(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		Fail(w, badQuery("Unsupported query parameters"))
		return
	}
	e, err := repo.GetLog(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	writeJSON(w, 200, logView(r, *e, nil, true))
}
func (h *Handlers) UserLogs(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	if _, err := h.Store.Users().Get(r.Context(), resolved(r).ID, id); err != nil {
		h.logError(w, r, err)
		return
	}
	p, _, _, _, err := logParams(r, true)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	events, total, err := repo.SearchLogs(r.Context(), resolved(r).ID, &store.LogQuery{Op: "eq", Field: "user_id", Value: id}, p)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	h.writeLogs(w, r, events, total, p, nil, true, false)
}
