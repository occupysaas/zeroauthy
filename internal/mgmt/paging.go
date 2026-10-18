package mgmt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Page sizes (M6): Auth0 documents 50 as the default page size, and
// refuses more than 100.
const (
	DefaultPerPage = 50
	MaxPerPage     = 100
	// MaxPage bounds page so that page*per_page fits any int.
	MaxPage = 1<<31/MaxPerPage - 1
)

func badQuery(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_query_string", Message: fmt.Sprintf(format, args...)}
}

// Page reads page (from 0), per_page (1 to MaxPerPage, default
// DefaultPerPage) and include_totals. A malformed or out-of-range value is
// a *Error, 400 invalid_query_string.
func Page(r *http.Request) (page, perPage int, includeTotals bool, err error) {
	q := r.URL.Query()
	page, perPage = 0, DefaultPerPage
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > MaxPage {
			return 0, 0, false, badQuery("Query validation error: page must be an integer from 0 to %d", MaxPage)
		}
		page = n
	}
	if v := q.Get("per_page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPerPage {
			return 0, 0, false, badQuery("Query validation error: per_page must be an integer from 1 to %d", MaxPerPage)
		}
		perPage = n
	}
	includeTotals, err = boolParam(r, "include_totals", false)
	if err != nil {
		return 0, 0, false, err
	}
	return page, perPage, includeTotals, nil
}

// Fields reads fields (comma-separated) and include_fields (default true).
// No fields means every field.
func Fields(r *http.Request) (fields []string, include bool, err error) {
	for _, f := range strings.Split(r.URL.Query().Get("fields"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			fields = append(fields, f)
		}
	}
	include, err = boolParam(r, "include_fields", true)
	if err != nil {
		return nil, false, err
	}
	return fields, include, nil
}

func boolParam(r *http.Request, name string, def bool) (bool, error) {
	switch v := r.URL.Query().Get(name); v {
	case "":
		return def, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, badQuery("Query validation error: %s must be true or false", name)
}

// alwaysProjected are the fields every projection keeps (M7).
var alwaysProjected = []string{"tenant"}

// Project returns v's JSON object members selected by fields: with include
// only those listed, otherwise all but those. tenant is always kept (M7).
// No fields returns every member. v must encode as a JSON object.
func Project(v any, fields []string, include bool) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var all map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		return nil
	}
	if len(fields) == 0 {
		return all
	}
	listed := map[string]bool{}
	for _, f := range fields {
		listed[f] = true
	}
	for _, f := range alwaysProjected {
		listed[f] = include
	}
	for k := range all {
		if listed[k] != include {
			delete(all, k)
		}
	}
	return all
}

// WriteList writes one page of items: a bare JSON array, or with
// includeTotals {<plural>, start, limit, total} (M6).
func WriteList[T any](w http.ResponseWriter, plural string, items []T, page, perPage int, includeTotals bool) {
	page, perPage = min(max(page, 0), MaxPage), min(max(perPage, 1), MaxPerPage)
	start := min(page*perPage, len(items))
	end := min(start+perPage, len(items))
	out := items[start:end]
	if out == nil {
		out = []T{}
	}
	if !includeTotals {
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{plural: out, "start": page * perPage, "limit": perPage, "total": len(items)})
}
