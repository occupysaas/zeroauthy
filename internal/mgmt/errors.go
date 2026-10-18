// Package mgmt holds the shared parts of zeroauthy's Management API
// (/api/v2/, Auth0's surface) and system API (/api/system/): bearer-token
// authentication of machine-to-machine clients and console operators,
// scope checks, Auth0's error shape, pagination and field projection
// (design §4.2, D-0039).
package mgmt

import (
	"encoding/json"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// WriteError writes an error in Auth0's Management API shape: error is the
// status text, errorCode is left out when empty.
//
// A 401 also gets `WWW-Authenticate: Bearer error="invalid_token"` and a 403
// insufficient_scope `Bearer error="insufficient_scope"` (RFC 6750 §3; not
// observed on Auth0, and harmless to its clients).
func WriteError(w http.ResponseWriter, status int, errorCode, message string) {
	switch {
	case status == http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	case status == http.StatusForbidden && errorCode == "insufficient_scope":
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	}
	body := mgmtapi.ManagementError{StatusCode: status, Error: http.StatusText(status), Message: message}
	if errorCode != "" {
		body.ErrorCode = &errorCode
	}
	writeJSON(w, status, body)
}

// Error is a failure a handler reports with Fail.
type Error struct {
	Status  int
	Code    string // errorCode
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Fail writes err: an *Error as itself, anything else as a 500 that does
// not reveal it.
func Fail(w http.ResponseWriter, err error) {
	if e, ok := err.(*Error); ok {
		WriteError(w, e.Status, e.Code, e.Message)
		return
	}
	WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteJSON writes a successful JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) { writeJSON(w, status, v) }
