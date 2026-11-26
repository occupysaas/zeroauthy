// Package myaccount serves Auth0's My Account API at /me/v1 on tenant
// hosts (Plan 42a, D-0210): a signed-in user's own authentication methods
// and the factors the tenant offers.
package myaccount

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// Problem is the API's error body (api/myaccount.yaml ErrorResponse).
type Problem struct {
	Type       string            `json:"type"`
	Status     int               `json:"status"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail"`
	Validation []ValidationError `json:"validation_errors,omitempty"`
}

// ValidationError names one invalid request member.
type ValidationError struct {
	Detail  string `json:"detail"`
	Field   string `json:"field,omitempty"`
	Pointer string `json:"pointer,omitempty"`
	Source  string `json:"source,omitempty"`
}

func (p *Problem) Error() string { return p.Title + ": " + p.Detail }

func problem(status int, typ, title, detail string) *Problem {
	return &Problem{Type: typ, Status: status, Title: title, Detail: detail}
}

func unauthorized(detail string) *Problem {
	return problem(http.StatusUnauthorized, "unauthorized", "Unauthorized", detail)
}

func forbidden(scope string) *Problem {
	return problem(http.StatusForbidden, "insufficient_scope", "Forbidden", "The access token lacks the "+scope+" scope.")
}

func notFound(detail string) *Problem {
	return problem(http.StatusNotFound, "not_found", "Not Found", detail)
}

func badRequest(typ, detail string, v ...ValidationError) *Problem {
	p := problem(http.StatusBadRequest, typ, "Bad Request", detail)
	p.Validation = v
	return p
}

func conflict(typ, detail string) *Problem {
	return problem(http.StatusConflict, typ, "Conflict", detail)
}

func serverError() *Problem {
	return problem(http.StatusInternalServerError, "internal_error", "Internal Server Error", "The request could not be completed.")
}

// maxCorrelationID bounds an echoed x-correlation-id; longer values are
// replaced by the request ID.
const maxCorrelationID = 64

// correlationID is the request's x-correlation-id, or zeroauthy's
// request ID when it is absent, too long or not printable ASCII.
func correlationID(r *http.Request) string {
	v := r.Header.Get("x-correlation-id")
	ok := v != "" && len(v) <= maxCorrelationID
	for i := 0; ok && i < len(v); i++ {
		ok = v[i] > 0x20 && v[i] < 0x7f
	}
	if ok {
		return v
	}
	return middleware.GetReqID(r.Context())
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("x-correlation-id", correlationID(r))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, r *http.Request, p *Problem) {
	writeJSON(w, r, p.Status, p)
}
