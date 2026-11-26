package myorg

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// decode reads a JSON object body into dst, refusing other media types
// (415), unknown members and trailing data (400).
func decode(r *http.Request, dst any) *Problem {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return problem(http.StatusUnsupportedMediaType, "unsupported_media_type", "Unsupported Media Type", "The body must be application/json.")
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return badRequest("invalid_body", "The body is too large or unreadable.")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		detail := "malformed JSON"
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			detail = "member " + te.Field + " has the wrong type"
		} else if strings.HasPrefix(err.Error(), "json: unknown field ") {
			detail = "unknown member " + strings.TrimPrefix(err.Error(), "json: unknown field ")
		}
		return badRequest("invalid_body", "The body is not a valid request: "+detail)
	}
	if dec.More() {
		return badRequest("invalid_body", "The body has trailing data.")
	}
	return nil
}

func invalidQuery(field, detail string) *Problem {
	return badRequest("invalid_query", detail, ValidationError{Detail: detail, Field: field, Source: "query"})
}

// page reads from, take (1..100, default 50) and include_totals.
func page(r *http.Request) (store.OrgPage, *Problem) {
	q := r.URL.Query()
	p := store.OrgPage{From: q.Get("from"), Take: 50}
	if v := q.Get("take"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return p, invalidQuery("take", "take must be 1 to 100.")
		}
		p.Take = n
	}
	if len(p.From) > 1000 {
		return p, invalidQuery("from", "from is too long.")
	}
	if v := q.Get("include_totals"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return p, invalidQuery("include_totals", "include_totals must be true or false.")
		}
		p.IncludeTotals = b
	}
	return p, nil
}

// fieldFilter is fields/include_fields: keep reports whether a member is
// returned.
type fieldFilter struct {
	set     map[string]bool
	include bool
}

func fieldsOf(r *http.Request) (fieldFilter, *Problem) {
	q := r.URL.Query()
	f := fieldFilter{include: true}
	if v := q.Get("include_fields"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return f, invalidQuery("include_fields", "include_fields must be true or false.")
		}
		f.include = b
	}
	if v := q.Get("fields"); v != "" {
		if len(v) > 255 {
			return f, invalidQuery("fields", "fields is too long.")
		}
		f.set = map[string]bool{}
		for _, name := range strings.Split(v, ",") {
			f.set[strings.TrimSpace(name)] = true
		}
	}
	return f, nil
}

func (f fieldFilter) keep(name string) bool {
	if f.set == nil {
		return true
	}
	return f.set[name] == f.include
}

func (f fieldFilter) apply(m map[string]any) map[string]any {
	for k := range m {
		if !f.keep(k) {
			delete(m, k)
		}
	}
	return m
}

func timeString(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// fail answers err: a problem, not found, or a logged server error.
func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	var p *Problem
	switch {
	case errors.As(err, &p):
	case errors.Is(err, store.ErrNotFound):
		p = notFound("The resource does not exist.")
	default:
		h.log().ErrorContext(r.Context(), "my org: "+what, "err", err)
		p = serverError()
	}
	writeProblem(w, r, p)
}
