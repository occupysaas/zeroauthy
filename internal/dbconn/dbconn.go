// Package dbconn serves the Authentication API's database-connection
// endpoints (/dbconnections/*).
package dbconn

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// maxBodyBytes bounds a request body.
const maxBodyBytes = 64 << 10

// Handlers serves the /dbconnections endpoints.
type Handlers struct {
	Protection        *protection.Service
	Store             store.Store
	Database          *identity.Database
	Mailer            email.Mailer // used by password-reset sends
	Email             *email.Service
	TrustProxyHeaders bool
	Log               *slog.Logger
	Now               func() time.Time
	Go                func(func()) // runs email sending; nil = go statement
	// Verification sends the verification email after a signup; nil sends
	// none.
	Verification SignupVerifier
}

// SignupVerifier sends a new user the email that verifies their address,
// without holding up the response. login.VerificationMailer implements it.
type SignupVerifier interface {
	SendInBackground(res tenant.Resolved, u *store.User, clientID, lang string)
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	httpx.WriteError(w, status, code, desc)
}

// internal logs err and answers 500 server_error.
func (h *Handlers) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.log().ErrorContext(r.Context(), "dbconnections: "+what, "err", err)
	writeErr(w, http.StatusInternalServerError, "server_error", "internal error")
}

// parseBody reads a JSON object or a form-encoded body into a map. On any
// problem it writes a 400 invalid_request and returns false.
func parseBody(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	bad := func(desc string) (map[string]any, bool) {
		writeErr(w, http.StatusBadRequest, "invalid_request", desc)
		return nil, false
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			return bad("the request body could not be read")
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		var m map[string]any
		if err := dec.Decode(&m); err != nil || m == nil {
			return bad("the request body must be a JSON object")
		}
		if dec.More() {
			return bad("the request body must be a single JSON object")
		}
		if _, err := dec.Token(); err != io.EOF {
			return bad("the request body must be a single JSON object")
		}
		return m, true
	case "application/x-www-form-urlencoded":
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			return bad("the request body is not valid form data")
		}
		m := make(map[string]any, len(r.PostForm))
		for k, v := range r.PostForm {
			if len(v) != 1 {
				return bad(k + " must not be repeated")
			}
			m[k] = v[0]
		}
		return m, true
	}
	return bad("content type must be application/json or application/x-www-form-urlencoded")
}

func (h *Handlers) protectionService() *protection.Service {
	if h.Protection != nil {
		return h.Protection
	}
	return &protection.Service{Store: h.Store, Now: h.Now, Log: h.Log}
}
