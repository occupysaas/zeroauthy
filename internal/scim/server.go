package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Strategies whose connections accept SCIM (Auth0: SAML, OpenID Connect,
// Okta Workforce, Microsoft Entra ID).
var Strategies = []string{"samlp", "oidc", "okta", "waad"}

// MaxBody bounds a SCIM request body.
const MaxBody = 256 << 10

// MediaType is the SCIM media type (RFC 7644 §3.1).
const MediaType = "application/scim+json"

// HashToken is how SCIM tokens are stored and looked up.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Handler serves /scim/v2/connections/{connection_id}.
type Handler struct {
	Store store.Store
	// EndSessions ends a deactivated user's sessions inside tx, with
	// back-channel logout (production: logout.Service.EndUserSessions);
	// nil deletes the sessions.
	EndSessions func(ctx context.Context, tx store.Store, tenantID, userID string) error
	// DeleteUser deletes a user as DELETE /api/v2/users/{id} does (events,
	// logout); nil deletes through the store.
	DeleteUser func(r *http.Request, userID string) error
	Now        func() time.Time
	Log        *slog.Logger
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Error is an RFC 7644 §3.12 error.
type Error struct {
	Status   int
	SCIMType string
	Detail   string
}

func (e *Error) Error() string { return e.Detail }

func errorf(status int, scimType, detail string) *Error {
	return &Error{Status: status, SCIMType: scimType, Detail: detail}
}

var (
	errUnauthorized = errorf(http.StatusUnauthorized, "", "Invalid or expired SCIM token.")
	errNotFound     = errorf(http.StatusNotFound, "", "Resource not found.")
	errBody         = errorf(http.StatusBadRequest, "invalidSyntax", "The request body is not a valid SCIM resource.")
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	if !errors.As(err, &e) {
		h.log().ErrorContext(r.Context(), "scim: request failed", "err", err)
		e = errorf(http.StatusInternalServerError, "", "Internal error.")
	}
	body := map[string]any{"schemas": []string{ErrorURN}, "status": strconv.Itoa(e.Status), "detail": e.Detail}
	if e.SCIMType != "" {
		body["scimType"] = e.SCIMType
	}
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
	}
	writeJSON(w, e.Status, body)
}

// call is one authorized SCIM request.
type call struct {
	tenant  *store.Tenant
	origin  string
	conn    *store.Connection
	config  *store.SCIMConfig
	mapping Mapping
	uidPath Path
	token   *store.SCIMToken
}

// Routes returns the router mounted at /scim/v2/connections/{connection_id}.
func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/ServiceProviderConfig", h.serviceProviderConfig)
	r.Get("/ResourceTypes", h.resourceTypes)
	r.Get("/Schemas", h.schemas)
	r.Get("/Users", h.with("get:users", h.listUsers))
	r.Post("/Users", h.with("post:users", h.createUser))
	r.Get("/Users/{id}", h.with("get:users", h.getUser))
	r.Put("/Users/{id}", h.with("put:users", h.replaceUser))
	r.Patch("/Users/{id}", h.with("patch:users", h.patchUser))
	r.Delete("/Users/{id}", h.with("delete:users", h.deleteUser))
	r.Get("/Groups", h.with("get:groups", h.listGroups))
	r.Post("/Groups", h.with("post:groups", h.createGroup))
	r.Get("/Groups/{id}", h.with("get:groups", h.getGroup))
	r.Put("/Groups/{id}", h.with("put:groups", h.replaceGroup))
	r.Patch("/Groups/{id}", h.with("patch:groups", h.patchGroup))
	r.Delete("/Groups/{id}", h.with("delete:groups", h.deleteGroup))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { h.fail(w, r, errNotFound) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		h.fail(w, r, errorf(http.StatusMethodNotAllowed, "", "Method not allowed."))
	})
	return r
}

// authorize resolves the token, the connection and its configuration. A
// token only acts on its own connection (D-0150 anti-goal).
func (h *Handler) authorize(r *http.Request, scope string) (*call, error) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		return nil, errNotFound
	}
	connID := chi.URLParamFromCtx(r.Context(), "connection_id")
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" || len(raw) > 512 {
		return nil, errUnauthorized
	}
	ctx := r.Context()
	if !store.DirectoryAvailable(h.Store) {
		return nil, errorf(http.StatusNotImplemented, "", "SCIM is not available on this storage.")
	}
	tok, err := h.Store.Directory().UseSCIMToken(ctx, res.Tenant.ID, HashToken(raw), h.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !tok.Active(h.now()) || tok.ConnectionID != connID {
		return nil, errUnauthorized
	}
	if !slices.Contains(tok.Scopes, scope) {
		return nil, errorf(http.StatusForbidden, "", "The SCIM token lacks the scope "+scope+".")
	}
	conn, err := h.Store.Connections().Get(ctx, res.Tenant.ID, connID)
	if errors.Is(err, store.ErrNotFound) || err == nil && !slices.Contains(Strategies, conn.Strategy) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	cfg, err := h.Store.Directory().GetSCIMConfig(ctx, res.Tenant.ID, connID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	m, err := ParseMapping(cfg.Mapping)
	if err != nil {
		return nil, err
	}
	uid := cfg.UserIDAttribute
	if uid == "" {
		uid = DefaultUserIDAttribute
	}
	up, err := ParsePath(uid)
	if err != nil {
		return nil, err
	}
	return &call{tenant: res.Tenant, origin: res.Origin(), conn: conn, config: cfg, mapping: m, uidPath: up, token: tok}, nil
}

func (h *Handler) with(scope string, fn func(http.ResponseWriter, *http.Request, *call) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := h.authorize(r, scope)
		if err == nil {
			err = fn(w, r, c)
		}
		if err != nil {
			h.fail(w, r, err)
		}
	}
}

// readBody decodes a bounded JSON object body.
func readBody(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		return errorf(http.StatusRequestEntityTooLarge, "", "The request body is too large.")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(v); err != nil || dec.More() {
		return errBody
	}
	return nil
}

func (c *call) base() string {
	return strings.TrimSuffix(c.origin, "/") + "/scim/v2/connections/" + c.conn.ID
}

// page reads startIndex (1-based) and count (default and maximum 100).
func page(r *http.Request) (start, count int, err error) {
	start, count = 1, 100
	q := r.URL.Query()
	if v := q.Get("startIndex"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return 0, 0, errorf(http.StatusBadRequest, "invalidValue", "startIndex must be an integer.")
		}
		start = max(n, 1)
	}
	if v := q.Get("count"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return 0, 0, errorf(http.StatusBadRequest, "invalidValue", "count must be an integer.")
		}
		count = min(max(n, 0), 100)
	}
	return start, count, nil
}

func listResponse(total, start int, resources []any) map[string]any {
	if resources == nil {
		resources = []any{}
	}
	return map[string]any{"schemas": []string{ListResponseURN}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources}
}

func meta(kind, location string, created, modified time.Time) map[string]any {
	return map[string]any{"resourceType": kind, "created": created.UTC().Format(time.RFC3339Nano), "lastModified": modified.UTC().Format(time.RFC3339Nano), "location": location}
}
