// Package httpx holds small HTTP helpers shared by handlers.
package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorBody is the error shape used by every JSON API endpoint.
type ErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an ErrorBody.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, ErrorBody{Error: code, ErrorDescription: description})
}
