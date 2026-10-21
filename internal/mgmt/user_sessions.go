package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Sessions and refresh tokens of a user (U8, D-0043): Auth0's objects, the
// lists by checkpoint paging only, and deletes that all answer 202 {}.

var (
	errNoSession      = &Error{Status: http.StatusNotFound, Message: "The session does not exist."}
	errNoRefreshToken = &Error{Status: http.StatusNotFound, Message: "The refresh token does not exist."}
)

// takeDescription is the suffix Auth0 puts on take's validation errors.
const takeDescription = "(Number of results per page. Defaults to 50)."

var errBadCheckpoint = &Error{Status: http.StatusBadRequest, Code: "invalid_query_string",
	Message: "The checkpoint ID provided in the 'from' parameter has expired or is invalid, please remove the checkpoint ID and try again"}

// checkpointTake reads take for the session and refresh-token lists: 1 to
// maxTake, 50 when absent.
func checkpointTake(r *http.Request) (int, error) {
	q := r.URL.Query()
	if !q.Has("take") {
		return DefaultPerPage, nil
	}
	v := q.Get("take")
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		return 0, badQuery("Query validation error: 'Expected type integer but found type string' on property take %s", takeDescription)
	case n > maxTake:
		return 0, badQuery("Query validation error: 'Value %d is greater than maximum %d' on property take %s", n, maxTake, takeDescription)
	case n < 1:
		return 0, badQuery("Query validation error: 'Value %d is less than minimum 1' on property take %s", n, takeDescription)
	}
	return n, nil
}

// timeCursor is the position after an item of a newest-first list: its
// creation time and ID. Items sort by creation time, then ID, descending, so
// the next page holds those that sort before the cursor and an item added or
// deleted meanwhile neither repeats nor skips another.
type timeCursor struct {
	T  int64  `json:"t"` // UnixNano
	ID string `json:"i"`
}

func encodeTimeCursor(t time.Time, id string) string {
	b, _ := json.Marshal(timeCursor{T: t.UnixNano(), ID: id})
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + string(b)))
}

func decodeTimeCursor(from string) *timeCursor {
	b, err := base64.RawURLEncoding.DecodeString(from)
	raw, ok := strings.CutPrefix(string(b), cursorPrefix)
	if err != nil || !ok {
		return nil
	}
	var c timeCursor
	if json.Unmarshal([]byte(raw), &c) != nil || c.ID == "" || len(c.ID) > 256 {
		return nil
	}
	return &c
}

// checkpointList writes one page of items, newest first, as {plural: [...],
// next}: next is the cursor of the last item whenever the page is not empty
// (U8) and absent otherwise.
func checkpointList[T any](w http.ResponseWriter, r *http.Request, plural string, items []T, key func(T) (time.Time, string), view func(T) any) {
	take, err := checkpointTake(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if from := r.URL.Query().Get("from"); from != "" {
		c := decodeTimeCursor(from)
		if c == nil {
			Fail(w, errBadCheckpoint)
			return
		}
		items = slices.DeleteFunc(slices.Clone(items), func(it T) bool {
			t, id := key(it)
			n := t.UnixNano()
			return n > c.T || (n == c.T && id >= c.ID)
		})
	}
	if len(items) > take {
		items = items[:take]
	}
	views := make([]any, len(items))
	for i, it := range items {
		views[i] = view(it)
	}
	out := map[string]any{plural: views}
	if len(items) > 0 {
		t, id := key(items[len(items)-1])
		out["next"] = encodeTimeCursor(t, id)
	}
	writeJSON(w, http.StatusOK, out)
}

// userForSessions checks the user ID and that the user exists.
func (h *Handlers) userForSessions(r *http.Request, id string) error {
	if !validUserID(id) {
		return badUserID(id)
	}
	_, err := h.getUser(r, id)
	return err
}

func sessionLive(s *store.LoginSession, now time.Time) bool {
	return now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

// tokenLive reports whether t is neither revoked, rotated nor expired.
func tokenLive(t *store.RefreshToken, now time.Time) bool {
	return t.RevokedAt == nil && t.RotatedAt == nil &&
		(t.ExpiresAt.IsZero() || now.Before(t.ExpiresAt)) &&
		(t.IdleExpiresAt.IsZero() || now.Before(t.IdleExpiresAt))
}

func sessionDevice(s *store.LoginSession) map[string]any {
	return map[string]any{
		"initial_user_agent": s.InitialUserAgent, "initial_ip": s.InitialIP,
		"last_user_agent": s.LastUserAgent, "last_ip": s.LastIP,
	}
}

// sessionJSON renders a session as Auth0 does. The authentication method is
// always pwd: database logins are the only kind zeroauthy has.
func sessionJSON(s *store.LoginSession) map[string]any {
	clients := make([]map[string]any, len(s.ClientIDs))
	for i, c := range s.ClientIDs {
		clients[i] = map[string]any{"client_id": c}
	}
	return map[string]any{
		"id": s.ID, "user_id": s.UserID,
		"created_at": userTime(s.CreatedAt), "updated_at": userTime(s.UpdatedAt),
		"authenticated_at": userTime(s.AuthenticatedAt),
		"authentication":   map[string]any{"methods": []map[string]any{{"name": "pwd", "timestamp": userTime(s.AuthenticatedAt)}}},
		"idle_expires_at":  userTime(s.IdleExpiresAt), "expires_at": userTime(s.ExpiresAt),
		"device": sessionDevice(s), "clients": clients,
		"last_interacted_at": userTime(s.LastInteractedAt),
		"cookie":             map[string]any{"mode": "persistent"},
	}
}

// refreshTokenJSON renders a token as Auth0 does. The device comes from the
// token's session, when it still exists. A token for /userinfo only lists
// the tenant's userinfo audience as its resource server. IDs keep
// zeroauthy's format, not Auth0's dcr_ prefix.
func refreshTokenJSON(t *store.RefreshToken, sess *store.LoginSession, userinfoAudience string) map[string]any {
	nullable := func(at time.Time) any {
		if at.IsZero() {
			return nil
		}
		return userTime(at)
	}
	audience := t.Audience
	if audience == "" {
		audience = userinfoAudience
	}
	var sessionID, exchanged any
	if t.SessionID != "" {
		sessionID = t.SessionID
	}
	if t.RotatedAt != nil {
		exchanged = userTime(*t.RotatedAt)
	}
	m := map[string]any{
		"id": t.ID, "user_id": t.UserID, "created_at": userTime(t.CreatedAt),
		"idle_expires_at": nullable(t.IdleExpiresAt), "expires_at": nullable(t.ExpiresAt),
		"client_id": t.ClientID, "session_id": sessionID, "rotating": t.Rotating,
		"resource_servers":  []map[string]any{{"audience": audience, "scopes": strings.Join(t.Scopes, " ")}},
		"last_exchanged_at": exchanged,
	}
	if sess != nil {
		m["device"] = sessionDevice(sess)
	}
	return m
}

func (h *Handlers) userinfoAudience(r *http.Request) string {
	res, _ := tenant.FromContext(r.Context())
	return res.Issuer() + "userinfo"
}

// GetUserSessions lists the user's unexpired sessions, newest first.
func (h *Handlers) GetUserSessions(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	all, err := h.Store.Sessions().ListByUser(r.Context(), resolved(r).ID, id)
	if err != nil {
		Fail(w, internalError(h, r, "list sessions", err))
		return
	}
	now := h.now()
	all = slices.DeleteFunc(all, func(s *store.LoginSession) bool { return !sessionLive(s, now) })
	checkpointList(w, r, "sessions", all,
		func(s *store.LoginSession) (time.Time, string) { return s.CreatedAt, s.ID },
		func(s *store.LoginSession) any { return sessionJSON(s) })
}

// DeleteUserSessions ends every session of the user and bumps the user's
// version, in one transaction. Refresh tokens are not revoked (U8).
func (h *Handlers) DeleteUserSessions(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	ctx, tn := r.Context(), resolved(r)
	// The bump comes first and locks the user, so a grant minting for the
	// user runs wholly before or after this (its check sees the bump).
	var n int
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Users().BumpVersion(ctx, tn.ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var err error
		n, err = tx.Sessions().DeleteByUser(ctx, tn.ID, id)
		return err
	})
	if err != nil {
		Fail(w, internalError(h, r, "delete sessions", err))
		return
	}
	h.audit(r, "delete user sessions", "user_id", id, "sessions", n)
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

// GetUserRefreshTokens lists the user's live refresh tokens, newest first.
func (h *Handlers) GetUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	ctx, tn := r.Context(), resolved(r)
	all, err := h.Store.RefreshTokens().ListByUser(ctx, tn.ID, id)
	if err != nil {
		Fail(w, internalError(h, r, "list refresh tokens", err))
		return
	}
	now := h.now()
	all = slices.DeleteFunc(all, func(t *store.RefreshToken) bool { return !tokenLive(t, now) })
	sessions := map[string]*store.LoginSession{}
	audience := h.userinfoAudience(r)
	checkpointList(w, r, "tokens", all,
		func(t *store.RefreshToken) (time.Time, string) { return t.CreatedAt, t.ID },
		func(t *store.RefreshToken) any {
			return refreshTokenJSON(t, h.tokenSession(r, t, sessions), audience)
		})
}

// tokenSession returns the live session of t, if any, caching by ID.
func (h *Handlers) tokenSession(r *http.Request, t *store.RefreshToken, cache map[string]*store.LoginSession) *store.LoginSession {
	if t.SessionID == "" {
		return nil
	}
	if s, ok := cache[t.SessionID]; ok {
		return s
	}
	s, err := h.Store.Sessions().Get(r.Context(), t.TenantID, t.SessionID)
	if err != nil {
		s = nil
	}
	cache[t.SessionID] = s
	return s
}

// DeleteUserRefreshTokens revokes every refresh token of the user and bumps
// the user's version.
func (h *Handlers) DeleteUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	ctx, tn, now := r.Context(), resolved(r), h.now()
	// Bump first, as for sessions: a refresh rotating now is refused rather
	// than minting a token after the revocation.
	var n int
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Users().BumpVersion(ctx, tn.ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var err error
		n, err = tx.RefreshTokens().RevokeByUser(ctx, tn.ID, id, now)
		return err
	})
	if err != nil {
		Fail(w, internalError(h, r, "delete refresh tokens", err))
		return
	}
	h.audit(r, "delete user refresh tokens", "user_id", id, "tokens", n)
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

// GetSession returns one unexpired session.
func (h *Handlers) GetSession(w http.ResponseWriter, r *http.Request, id string) {
	if !storableText(id) {
		Fail(w, errNoSession)
		return
	}
	s, err := h.Store.Sessions().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !sessionLive(s, h.now())) {
		Fail(w, errNoSession)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get session", err))
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON(s))
}

// DeleteSession ends one session, also when there is none.
func (h *Handlers) DeleteSession(w http.ResponseWriter, r *http.Request, id string) {
	if !storableText(id) { // no session has it
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	err := h.Store.Sessions().Delete(r.Context(), resolved(r).ID, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		Fail(w, internalError(h, r, "delete session", err))
		return
	}
	if err == nil {
		h.audit(r, "delete session", "session_id", id)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

// GetRefreshToken returns one live refresh token.
func (h *Handlers) GetRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	if !storableText(id) {
		Fail(w, errNoRefreshToken)
		return
	}
	t, err := h.Store.RefreshTokens().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !tokenLive(t, h.now())) {
		Fail(w, errNoRefreshToken)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get refresh token", err))
		return
	}
	writeJSON(w, http.StatusOK, refreshTokenJSON(t, h.tokenSession(r, t, map[string]*store.LoginSession{}), h.userinfoAudience(r)))
}

// DeleteRefreshToken revokes a refresh token and its rotation family, also
// when there is no such token.
func (h *Handlers) DeleteRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	if !storableText(id) { // no token has it
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	ctx, tn := r.Context(), resolved(r)
	t, err := h.Store.RefreshTokens().Get(ctx, tn.ID, id)
	if err == nil {
		// Lock the user first, as a rotation does: one in flight commits
		// wholly before this (and its successor is in the family revoked
		// here) or after it (and finds its token revoked).
		err = h.Store.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.Users().GetForUpdate(ctx, tn.ID, t.UserID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			return tx.RefreshTokens().RevokeFamily(ctx, tn.ID, t.FamilyID, h.now())
		})
		if err == nil {
			h.audit(r, "delete refresh token", "token_id", id)
		}
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		Fail(w, internalError(h, r, "delete refresh token", err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{})
}
