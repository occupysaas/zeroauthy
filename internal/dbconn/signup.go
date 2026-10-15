package dbconn

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Signup implements POST /dbconnections/signup (D-0018).
func (h *Handlers) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	body, ok := parseBody(w, r)
	if !ok {
		return
	}
	str := func(k string) (string, bool) {
		v, present := body[k]
		if !present || v == nil {
			return "", true
		}
		s, isStr := v.(string)
		return s, isStr
	}
	fields := map[string]string{}
	for _, k := range []string{"client_id", "connection", "email", "password", "username", "given_name", "family_name", "name", "nickname", "picture"} {
		s, ok := str(k)
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid_request", k+" must be a string")
			return
		}
		fields[k] = s
	}
	for _, k := range []string{"client_id", "connection", "password"} {
		if fields[k] == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", k+" is required")
			return
		}
	}
	meta, err := userMetadata(body["user_metadata"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenantID := res.Tenant.ID
	if !h.IPThrottle.Attempt(identity.IPThrottleKey(tenantID, httpx.ClientIP(r, h.TrustProxyHeaders))) {
		writeErr(w, http.StatusTooManyRequests, "too_many_requests", "too many sign-ups from this address; try again later")
		return
	}
	if _, err := h.Store.Clients().Get(ctx, tenantID, fields["client_id"]); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "unknown client")
		return
	} else if err != nil {
		h.internal(w, r, "load client", err)
		return
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, fields["connection"])
	if errors.Is(err, store.ErrNotFound) || (err == nil && (conn.Strategy != store.StrategyDatabase || !slices.Contains(conn.EnabledClients, fields["client_id"]))) {
		writeErr(w, http.StatusBadRequest, "invalid_signup", "the connection does not exist or is not enabled for this application")
		return
	} else if err != nil {
		h.internal(w, r, "load connection", err)
		return
	}
	user, err := h.Database.Signup(ctx, conn, identity.SignupInput{
		Email: fields["email"], Username: fields["username"], Password: fields["password"],
		GivenName: fields["given_name"], FamilyName: fields["family_name"], Name: fields["name"],
		Nickname: fields["nickname"], Picture: fields["picture"], UserMetadata: meta,
	})
	var pe *identity.PolicyError
	switch {
	case errors.Is(err, identity.ErrSignupDisabled):
		writeErr(w, http.StatusBadRequest, "invalid_signup", "sign-up is disabled for this connection")
		return
	case errors.Is(err, identity.ErrUserExists):
		writeErr(w, http.StatusConflict, "user_exists", "the user already exists")
		return
	case errors.As(err, &pe) && pe.Key != "" && strings.HasPrefix(pe.Key, "zeroauthy.signup.password"):
		writeErr(w, http.StatusBadRequest, "invalid_password", pe.Reason)
		return
	case errors.As(err, &pe):
		writeErr(w, http.StatusBadRequest, "invalid_signup", pe.Reason)
		return
	case err != nil:
		h.internal(w, r, "sign up", err)
		return
	}
	out := map[string]any{"_id": strings.TrimPrefix(user.UserID, store.StrategyDatabase+"|"), "email_verified": user.EmailVerified, "email": user.Email}
	for k, v := range map[string]string{"username": user.Username, "given_name": user.GivenName, "family_name": user.FamilyName,
		"name": user.Name, "nickname": user.Nickname, "picture": user.Picture} {
		if v != "" {
			out[k] = v
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// userMetadata enforces Auth0's documented signup limits: at most ten
// properties, names up to 100 characters, string values up to 500.
func userMetadata(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("user_metadata must be an object")
	}
	if len(m) > 10 {
		return nil, errors.New("user_metadata may have at most 10 properties")
	}
	for k, val := range m {
		s, ok := val.(string)
		if !ok || utf8.RuneCountInString(k) > 100 || utf8.RuneCountInString(s) > 500 {
			return nil, fmt.Errorf("user_metadata.%s must be a string of at most 500 characters with a name of at most 100", k)
		}
	}
	return m, nil
}
