package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	// tryLimit calls per tryWindow per operator (D-0042). Reaching the limit
	// locks the operator out for tryWindow.
	tryLimit  = 10
	tryWindow = time.Minute
)

var errScriptRuntime = &Error{Status: http.StatusServiceUnavailable, Code: "script_runtime_unavailable", Message: "The custom database script runtime is not available"}

// scriptErrorName is the class name a script's error is reported under.
var scriptErrorName = map[string]string{
	customdb.KindWrongCredentials: "WrongUsernameOrPasswordError",
	customdb.KindValidation:       "ValidationError",
	customdb.KindUnauthorized:     "UnauthorizedError",
	customdb.KindError:            "Error",
}

// tryResult is the ScriptTryResult of api/management.yaml; Result is the
// callback value as the script produced it.
type tryResult struct {
	Result     json.RawMessage `json:"result"`
	Error      *tryError       `json:"error"`
	Logs       []string        `json:"logs"`
	DurationMs int             `json:"duration_ms"`
}

type tryError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// tryBody decodes {"args": [...]} with numbers kept exact.
func tryBody(r *http.Request) ([]any, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	for k := range body {
		if k != "args" {
			return nil, badBody("unknown property %q", k)
		}
	}
	raw, ok := body["args"]
	if !ok || isNull(raw) {
		return nil, badBody("Missing required property: args")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args []any
	if err := dec.Decode(&args); err != nil {
		return nil, badBody("args must be an array")
	}
	return args, nil
}

// tryAllowed counts one call by operator against the limit.
func (h *Handlers) tryAllowed(operator string) bool {
	h.tryOnce.Do(func() { h.tryThrottle = identity.NewThrottle(tryLimit, tryWindow, tryWindow) })
	return h.tryThrottle.Attempt(operator)
}

// TryConnectionScript runs a connection's custom database script with test
// arguments and reports what it answered (D-0042, design section 5.4). The
// connection need not have its scripts switched on.
func (h *Handlers) TryConnectionScript(w http.ResponseWriter, r *http.Request, tenantName, id, script string) {
	args, err := tryBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	want, known := customdb.ScriptArgCounts[script]
	if !known || !slices.Contains(store.ScriptNames, script) {
		Fail(w, badBody("name must be one of %v", store.ScriptNames))
		return
	}
	if len(args) != want {
		Fail(w, badBody("the %s script takes %d argument(s), got %d", script, want, len(args)))
		return
	}
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	tn, err := h.Store.Tenants().GetByName(r.Context(), tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "try script", err))
		return
	}
	conn, err := h.Store.Connections().Get(r.Context(), tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "try script", err))
		return
	}
	if conn.CustomScripts[script] == "" {
		Fail(w, badBody("the connection has no %s script", script))
		return
	}
	caller, _ := CallerFrom(r.Context())
	if !h.tryAllowed(caller.UserID) {
		w.Header().Set("Retry-After", strconv.Itoa(int(tryWindow.Seconds())))
		h.logTry(r.Context(), tn.Name, id, script, caller.UserID, 0, "rate_limited")
		Fail(w, &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Message: "Too many script tries; wait a minute"})
		return
	}
	if h.Scripts == nil {
		h.logTry(r.Context(), tn.Name, id, script, caller.UserID, 0, "no_runtime")
		Fail(w, errScriptRuntime)
		return
	}

	var logs []string
	start := time.Now()
	raw, err := h.Scripts.Try(r.Context(), conn, script, args, func(l []string) { logs = l })
	took := time.Since(start)
	if logs == nil {
		logs = []string{}
	}
	out := tryResult{Result: json.RawMessage("null"), Logs: logs, DurationMs: int(took.Milliseconds())}
	outcome := "ok"
	var se *customdb.ScriptError
	switch {
	case err == nil:
		if len(bytes.TrimSpace(raw)) > 0 && !isNull(raw) {
			out.Result = raw
		}
	case errors.As(err, &se):
		outcome = "script_error"
		name := scriptErrorName[se.Kind]
		if name == "" {
			name = "Error"
		}
		out.Error = &tryError{Name: name, Message: se.Message}
	case errors.Is(err, customdb.ErrTimeout):
		outcome = "timeout"
		out.Error = &tryError{Name: "TimeoutError", Message: fmt.Sprintf("The script did not answer within %s", customdb.MaxDuration)}
	case errors.Is(err, customdb.ErrUnavailable):
		h.logTry(r.Context(), tn.Name, id, script, caller.UserID, took, "unavailable")
		h.log().WarnContext(r.Context(), "management API: try script: runtime unavailable", "err", err)
		Fail(w, errScriptRuntime)
		return
	case errors.Is(err, customdb.ErrNoScript):
		h.logTry(r.Context(), tn.Name, id, script, caller.UserID, took, "no_script")
		Fail(w, badBody("the connection has no %s script", script))
		return
	default:
		h.logTry(r.Context(), tn.Name, id, script, caller.UserID, took, "error")
		Fail(w, internalError(h, r, "try script", err))
		return
	}
	h.logTry(r.Context(), tn.Name, id, script, caller.UserID, took, outcome)
	writeJSON(w, http.StatusOK, out)
}

// logTry writes the one log line of a try: who ran which script, how long
// it took and how it ended. Arguments, results, console output, error
// messages and configuration are never logged.
func (h *Handlers) logTry(ctx context.Context, tenant, connection, script, operator string, took time.Duration, outcome string) {
	h.log().InfoContext(ctx, "try custom database script",
		"tenant", tenant, "connection", connection, "script", script, "operator", operator,
		"duration_ms", took.Milliseconds(), "outcome", outcome)
}
