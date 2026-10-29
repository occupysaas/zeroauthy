package mgmt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
	"github.com/zeroauthy/zeroauthy/internal/usersearch"
)

// VerificationSender sends a user the email that verifies their address.
// clientID is the application the email is for, or empty. Task 10's mailer
// implements it.
type VerificationSender interface {
	SendVerification(ctx context.Context, tenantID string, u *store.User, clientID, host string) error
}

// maxSearchResults is how deep offset paging reaches into a user search
// (U4).
const maxSearchResults = 1000

var (
	errUserNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_user", Message: "The user does not exist."}
	// errUserExists is Auth0's answer for a duplicate user (U2): its own
	// database reports it as an identity provider error.
	errUserExists         = &Error{Status: http.StatusConflict, Code: "auth0_idp_error", Message: "The user already exists."}
	errUserConnection     = &Error{Status: http.StatusBadRequest, Code: "inexistent_connection", Message: "The connection does not exist."}
	errSearchEngineV1     = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "You are not allowed to use search_engine=v1."}
	errPagingDepth        = &Error{Status: http.StatusBadRequest, Code: "invalid_paging", Message: "You can only page through the first 1000 records. See https://auth0.com/docs/users/search/v3/view-search-results-by-page#limitation"}
	errNoDatabaseIdentity = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The user has no database identity"}
	errWeakPassword       = &Error{Status: http.StatusBadRequest, Message: "PasswordStrengthError: Password is too weak"}
	errPasswordInHistory  = &Error{Status: http.StatusBadRequest, Message: "PasswordHistoryError: Password has previously been used"}
)

func badUserID(id string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Object didn't pass validation for format user-id: " + id}
}

// validUserID reports whether id has the form provider|id, in text a
// database can store.
func validUserID(id string) bool {
	provider, rest, ok := strings.Cut(id, "|")
	return ok && provider != "" && rest != "" && strings.TrimSpace(id) == id && storableText(id)
}

// storableText reports whether s is valid UTF-8 without NUL: no driver can
// store anything else (Postgres refuses both with SQLSTATE 22021).
func storableText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

var errUnstorableText = badBodyRaw("Payload validation error: strings must be valid UTF-8 without NUL characters.")

// errUnstorableQuery answers a query parameter that is not storableText.
var errUnstorableQuery = badQuery("Query validation error: strings must be valid UTF-8 without NUL characters.")

// checkQueryText refuses the request's query parameters names when one is
// not storableText: the store would refuse it with a driver error.
func checkQueryText(r *http.Request, names ...string) error {
	q := r.URL.Query()
	for _, n := range names {
		for _, v := range q[n] {
			if !storableText(v) {
				return errUnstorableQuery
			}
		}
	}
	return nil
}

// checkBodyText refuses a body with a string or object key, at any depth,
// that is not storableText. JSON decoding would silently turn invalid UTF-8
// into U+FFFD, so the raw bytes are checked too.
func checkBodyText(body map[string]json.RawMessage) error {
	var walk func(v any) bool
	walk = func(v any) bool {
		switch v := v.(type) {
		case string:
			return storableText(v)
		case []any:
			for _, x := range v {
				if !walk(x) {
					return false
				}
			}
		case map[string]any:
			for k, x := range v {
				if !storableText(k) || !walk(x) {
					return false
				}
			}
		}
		return true
	}
	for k, raw := range body {
		var v any
		if !storableText(k) || !utf8.Valid(raw) || json.Unmarshal(raw, &v) != nil || !walk(v) {
			return errUnstorableText
		}
	}
	return nil
}

func insufficientScope(scope string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "Insufficient scope, expected: " + scope}
}

// UserJSON renders u in Auth0's shape (U1). Fields without a value are left
// out; blocked appears only when true and the login fields only after the
// first login. Password hashes never appear.
func UserJSON(u *store.User) map[string]any {
	m := map[string]any{"user_id": u.UserID, "created_at": userTime(u.CreatedAt), "updated_at": userTime(u.UpdatedAt)}
	if u.Email != "" {
		m["email"] = u.Email
		m["email_verified"] = u.EmailVerified
	}
	for k, v := range map[string]string{"username": u.Username, "name": u.Name, "nickname": u.Nickname, "picture": u.Picture,
		"given_name": u.GivenName, "family_name": u.FamilyName} {
		if v != "" {
			m[k] = v
		}
	}
	if u.PhoneNumber != "" {
		m["phone_number"] = u.PhoneNumber
		m["phone_verified"] = u.PhoneVerified
	}
	// blocked appears only when true. Auth0 shows blocked:false once it has
	// been set, but the store cannot tell "set to false" from "never set";
	// a logged deviation (D-0043).
	if u.Blocked {
		m["blocked"] = true
	}
	if u.UserMetadata != nil {
		m["user_metadata"] = u.UserMetadata
	}
	if u.AppMetadata != nil {
		m["app_metadata"] = u.AppMetadata
	}
	ids := make([]map[string]any, len(u.Identities))
	for i := range u.Identities {
		ids[i] = identityJSON(&u.Identities[i])
	}
	m["identities"] = ids
	if u.LastLogin != nil {
		m["last_login"] = userTime(*u.LastLogin)
		m["logins_count"] = u.LoginsCount
		if u.LastIP != "" {
			m["last_ip"] = u.LastIP
		}
	}
	return m
}

// userTime is Auth0's timestamp: RFC 3339 in UTC with milliseconds.
func userTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func userViews(us []*store.User, fields []string, include bool) []map[string]any {
	out := make([]map[string]any, len(us))
	for i, u := range us {
		out[i] = ProjectKeeping(UserJSON(u), fields, include, nil)
	}
	return out
}

// fieldError maps a userrules problem to Auth0's error.
func fieldError(err error) error {
	var fe *userrules.FieldError
	if errors.As(err, &fe) {
		return &Error{Status: http.StatusBadRequest, Code: fe.Code, Message: fe.Message}
	}
	return err
}

// GetUsers lists or searches the tenant's users (U4).
func (h *Handlers) GetUsers(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetUsersParams) {
	q := r.URL.Query()
	if err := checkQueryText(r, "connection"); err != nil {
		Fail(w, err)
		return
	}
	switch q.Get("search_engine") {
	case "", "v2", "v3":
	case "v1":
		Fail(w, errSearchEngineV1)
		return
	default:
		Fail(w, badQuery("Query validation error: 'search_engine' must be v3"))
		return
	}
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if (page+1)*perPage > maxSearchResults {
		Fail(w, errPagingDepth)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tree, err := usersearch.Parse(q.Get("q"))
	if err != nil {
		Fail(w, searchError(err))
		return
	}
	sort, err := usersearch.ParseSort(q.Get("sort"))
	if err != nil {
		Fail(w, searchError(err))
		return
	}
	if c := q.Get("connection"); c != "" {
		leaf := &store.UserQuery{Op: store.QueryTerm, Field: "identities.connection", Kind: store.KindString, Value: c}
		if tree == nil {
			tree = leaf
		} else {
			tree = &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{tree, leaf}}
		}
	}
	// The parser only builds valid trees; anything the store would still
	// refuse is the caller's input, never a driver's text.
	if tree.Validate() != nil || sort.Validate() != nil {
		Fail(w, badQuery("invalid query"))
		return
	}
	got, total, err := h.Store.Users().List(r.Context(), resolved(r).ID, tree, sort, store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		Fail(w, internalError(h, r, "list users", err))
		return
	}
	out := userViews(got, fields, include)
	if !totals {
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "start": page * perPage, "limit": perPage, "length": len(out), "total": total})
}

// searchError is a usersearch error as a 400; search errors carry no
// errorCode, sort errors invalid_query_string (U4).
func searchError(err error) error {
	var se *usersearch.Error
	if errors.As(err, &se) {
		return &Error{Status: http.StatusBadRequest, Code: se.Code, Message: se.Message}
	}
	return badQuery("invalid query")
}

// GetUsersByEmail finds users by email, case-sensitively (U5).
func (h *Handlers) GetUsersByEmail(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetUsersByEmailParams) {
	email := r.URL.Query().Get("email")
	if email == "" {
		Fail(w, badQuery("Query validation error: 'Missing required property: email' on property email (Email address to search for (case-sensitive))."))
		return
	}
	if !storableText(email) {
		Fail(w, errUnstorableQuery)
		return
	}
	if identity.CheckEmail(email) != nil {
		Fail(w, badQuery("Query validation error: 'Object didn't pass validation for format email: %s' on property email (Email address to search for (case-sensitive)).", email))
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	got, err := h.Store.Users().FindByEmail(r.Context(), resolved(r).ID, email)
	if err != nil {
		Fail(w, internalError(h, r, "find users by email", err))
		return
	}
	writeJSON(w, http.StatusOK, userViews(got, fields, include))
}

// GetUser returns one user.
func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserParams) {
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	u, err := h.getUser(r, id)
	if err != nil {
		Fail(w, err)
		return
	}
	view := UserJSON(u)
	if caller, _ := CallerFrom(r.Context()); caller.Kind == M2M && slices.Contains(caller.Scopes, scopeIDPTokens) {
		// Upstream tokens: individual GET only, to a client granted
		// read:user_idp_tokens explicitly; never to operators (Plan 24).
		w.Header().Set("Cache-Control", "no-store")
		if err := h.addIDPTokens(r, u, view); err != nil {
			Fail(w, internalError(h, r, "read upstream tokens", err))
			return
		}
	}
	writeJSON(w, http.StatusOK, ProjectKeeping(view, fields, include, nil))
}

// scopeIDPTokens gates identities[].access_token and refresh_token.
const scopeIDPTokens = "read:user_idp_tokens"

// addIDPTokens adds each federated identity's stored upstream tokens to
// view's identities. An identity without a token record gets no fields.
func (h *Handlers) addIDPTokens(r *http.Request, u *store.User, view map[string]any) error {
	ids, _ := view["identities"].([]map[string]any)
	for i := range u.Identities {
		sub, ok, err := u.Identities[i].FederatedSubject()
		if err != nil || !ok || i >= len(ids) {
			continue
		}
		c, err := h.Store.Connections().GetByName(r.Context(), u.TenantID, u.Identities[i].Connection)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		key := store.FederatedIdentityKey{TenantID: u.TenantID, ConnectionID: c.ID, Subject: sub}
		sealed, err := h.Store.Federation().GetTokens(r.Context(), key)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrFederationUnavailable) {
			continue
		}
		if err != nil {
			return err
		}
		t, err := federation.OpenTokens(h.Wrapper, key, sealed)
		if err != nil {
			return err
		}
		ids[i]["access_token"] = t.AccessToken
		if t.RefreshToken != "" {
			ids[i]["refresh_token"] = t.RefreshToken
		}
	}
	return nil
}

func (h *Handlers) getUser(r *http.Request, id string) (*store.User, error) {
	u, err := h.Store.Users().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(h, r, "get user", err)
	}
	return u, nil
}

// userBody reads a POST or PATCH body. Unknown properties and wrong types
// are 400 invalid_body.
type userBody struct {
	body map[string]json.RawMessage
}

func unknownUserProperty(k string) *Error {
	return badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s (consider storing them in app_metadata or user_metadata. See \"Users Metadata\" in https://auth0.com/docs/api/v2/changes for more details)'.", k))
}

func badBodyRaw(message string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: message}
}

func wrongType(k, want string, raw json.RawMessage) *Error {
	return badBodyRaw(fmt.Sprintf("Payload validation error: 'Expected type %s but found type %s' on property %s.", want, jsonTypeOf(raw), k))
}

func jsonTypeOf(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "invalid"
	}
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	}
	return "object"
}

func (b userBody) str(k string) (string, error) {
	raw := b.body[k]
	var s string
	if isNull(raw) || json.Unmarshal(raw, &s) != nil {
		return "", wrongType(k, "string", raw)
	}
	return s, nil
}

func (b userBody) strPtr(k string, nullable bool) (*string, error) {
	if nullable && isNull(b.body[k]) {
		s := ""
		return &s, nil
	}
	s, err := b.str(k)
	return &s, err
}

func (b userBody) boolPtr(k string) (*bool, error) {
	raw := b.body[k]
	var v bool
	if isNull(raw) || json.Unmarshal(raw, &v) != nil {
		return nil, wrongType(k, "boolean", raw)
	}
	return &v, nil
}

func (b userBody) object(k string) (map[string]any, error) {
	raw := b.body[k]
	var v map[string]any
	if isNull(raw) || json.Unmarshal(raw, &v) != nil {
		return nil, wrongType(k, "object", raw)
	}
	return v, nil
}

func readCreateBody(body map[string]json.RawMessage) (*userrules.Create, error) {
	b := userBody{body}
	in := &userrules.Create{}
	strs := map[string]*string{
		"connection": &in.Connection, "email": &in.Email, "username": &in.Username, "password": &in.Password,
		"phone_number": &in.PhoneNumber, "user_id": &in.UserID, "name": &in.Name, "given_name": &in.GivenName,
		"family_name": &in.FamilyName, "nickname": &in.Nickname, "picture": &in.Picture,
	}
	bools := map[string]**bool{
		"email_verified": &in.EmailVerified, "phone_verified": &in.PhoneVerified, "blocked": &in.Blocked, "verify_email": &in.VerifyEmail,
	}
	var err error
	for _, k := range slices.Sorted(maps.Keys(body)) {
		switch {
		case strs[k] != nil:
			*strs[k], err = b.str(k)
		case bools[k] != nil:
			*bools[k], err = b.boolPtr(k)
		case k == "user_metadata":
			in.UserMetadata, err = b.object(k)
		case k == "app_metadata":
			in.AppMetadata, err = b.object(k)
		default:
			err = unknownUserProperty(k)
		}
		if err != nil {
			return nil, err
		}
	}
	return in, nil
}

// readPatchBody reads a PATCH body. given_name and family_name accept null,
// which removes them.
func readPatchBody(body map[string]json.RawMessage) (in *userrules.Patch, clientID string, err error) {
	b := userBody{body}
	in = &userrules.Patch{}
	strs := map[string]**string{
		"email": &in.Email, "username": &in.Username, "password": &in.Password, "phone_number": &in.PhoneNumber,
		"name": &in.Name, "given_name": &in.GivenName, "family_name": &in.FamilyName, "nickname": &in.Nickname, "picture": &in.Picture,
	}
	bools := map[string]**bool{
		"email_verified": &in.EmailVerified, "phone_verified": &in.PhoneVerified, "blocked": &in.Blocked, "verify_email": &in.VerifyEmail,
	}
	for _, k := range slices.Sorted(maps.Keys(body)) {
		switch {
		case strs[k] != nil:
			*strs[k], err = b.strPtr(k, k == "given_name" || k == "family_name")
		case bools[k] != nil:
			*bools[k], err = b.boolPtr(k)
		case k == "connection":
			in.Connection, err = b.str(k)
		case k == "client_id":
			clientID, err = b.str(k)
		case k == "user_metadata":
			err = json.Unmarshal(body[k], &in.UserMetadata)
		case k == "app_metadata":
			err = json.Unmarshal(body[k], &in.AppMetadata)
		default:
			err = unknownUserProperty(k)
		}
		if err != nil {
			if _, ok := err.(*Error); !ok {
				err = wrongType(k, "object", body[k])
			}
			return nil, "", err
		}
	}
	return in, clientID, nil
}

// database is the identity service over st, for the password history and
// the legacy store.
func (h *Handlers) database(st store.Store) *identity.Database {
	return &identity.Database{Store: st, Scripts: h.Scripts, Log: h.log(), Now: h.now}
}

// sendVerification sends u the verification email, if a sender is wired.
// A failure is logged; the write it follows stands.
func (h *Handlers) sendVerification(r *http.Request, u *store.User, clientID string) {
	if h.Verification == nil {
		h.log().DebugContext(r.Context(), "management API: verification email not sent: no sender is configured", "user_id", u.UserID)
		return
	}
	// Same domain choice as tickets: never the request's own Host.
	host, err := customdomain.SelectNotificationOrigin(r.Context(), h.Store, u.TenantID, r.Header.Get(CustomDomainHeader))
	if err != nil {
		h.log().WarnContext(r.Context(), "management API: verification email not sent: no usable domain", "user_id", u.UserID, "err", err)
		return
	}
	if err := h.Verification.SendVerification(r.Context(), u.TenantID, u, clientID, host); err != nil {
		h.log().ErrorContext(r.Context(), "management API: send verification email", "user_id", u.UserID, "err", err)
	}
}

// CreateUser creates a user on a database connection (U2).
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, ok := body["app_metadata"]; ok && !callerHas(r, "create:users_app_metadata") && !callerHas(r, "update:users_app_metadata") {
		Fail(w, insufficientScope("create:users_app_metadata"))
		return
	}
	if err := checkBodyText(body); err != nil {
		Fail(w, err)
		return
	}
	in, err := readCreateBody(body)
	if err != nil {
		Fail(w, err)
		return
	}
	if in.Connection == "" {
		Fail(w, badBodyRaw(userrules.MissingConnectionMessage))
		return
	}
	tn := resolved(r)
	ctx := r.Context()
	conn, err := h.Store.Connections().GetByName(ctx, tn.ID, in.Connection)
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.Strategy != store.StrategyDatabase) {
		Fail(w, errUserConnection)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "create user", err))
		return
	}
	if errs := userrules.CheckCreate(conn, in); len(errs) > 0 {
		Fail(w, fieldError(errs[0]))
		return
	}
	password := identity.EffectivePassword(conn, in.Password)
	if err := h.checkPassword(r, tn, "pre-user-registration", password); err != nil {
		Fail(w, err)
		return
	}
	now := h.now()
	deref := func(b *bool) bool { return b != nil && *b }
	u := &store.User{
		TenantID: tn.ID, Email: in.Email, EmailVerified: deref(in.EmailVerified), Username: in.Username,
		Name: in.Name, Nickname: in.Nickname, Picture: in.Picture, GivenName: in.GivenName, FamilyName: in.FamilyName,
		UserMetadata: in.UserMetadata, AppMetadata: in.AppMetadata, Blocked: deref(in.Blocked),
		PhoneNumber: in.PhoneNumber, PhoneVerified: deref(in.PhoneVerified), CreatedAt: now, UpdatedAt: now,
	}
	legacy := identity.IsLegacy(conn)
	ident := store.Identity{Connection: conn.Name, Provider: store.StrategyDatabase}
	var hash string
	if legacy {
		if ident.UserID, err = h.legacyCreate(r, conn, in, password); err != nil {
			Fail(w, err)
			return
		}
		u.UserID = store.StrategyDatabase + "|" + ident.UserID
	} else {
		u.UserID, ident.UserID = in.StoredUserID(), in.UserID
		if u.UserID == "" {
			ident.UserID = secrets.RandomHex(12)
			u.UserID = store.StrategyDatabase + "|" + ident.UserID
		}
		if hash, err = secrets.Hash(password); err != nil {
			Fail(w, internalError(h, r, "create user", err))
			return
		}
		ident.PasswordHash = hash
	}
	u.Identities = []store.Identity{ident}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, u); errors.Is(err, store.ErrConflict) {
			return errUserExists
		} else if err != nil {
			return err
		}
		if legacy {
			return h.database(tx).RecordLegacyPassword(ctx, conn, u.UserID, password)
		}
		return identity.RecordPassword(ctx, tx, conn, u.UserID, hash)
	})
	if err != nil {
		h.failTx(w, r, "create user", err)
		return
	}
	h.audit(r, "create user", "user_id", u.UserID, "connection", conn.Name)
	if (in.VerifyEmail != nil && *in.VerifyEmail) || (in.VerifyEmail == nil && !u.EmailVerified && u.Email != "") {
		h.sendVerification(r, u, "")
	}
	writeJSON(w, http.StatusCreated, UserJSON(u))
}

// legacyCreate creates the user in a legacy store: get_user (when the
// connection has it) must not know the email, then the create script runs,
// then get_user (or login, as sign-up does) gives the legacy user_id.
func (h *Handlers) legacyCreate(r *http.Request, conn *store.Connection, in *userrules.Create, password string) (string, error) {
	ctx := r.Context()
	c := h.Scripts
	if c == nil {
		return "", h.scriptFail(r, conn, store.ScriptCreate, customdb.ErrUnavailable)
	}
	p, err := c.GetUser(ctx, conn, in.Email)
	switch {
	case errors.Is(err, customdb.ErrNoScript):
	case err != nil:
		return "", h.scriptFail(r, conn, store.ScriptGetUser, err)
	case p != nil:
		return "", errUserExists
	}
	caller, _ := CallerFrom(ctx)
	err = c.Create(ctx, conn, customdb.CreateUser{
		Tenant: resolved(r).Name, ClientID: caller.ClientID, Connection: conn.Name, Email: in.Email, Password: password,
		Username: in.Username, UserMetadata: in.UserMetadata, AppMetadata: in.AppMetadata,
	})
	if err != nil {
		return "", h.scriptFail(r, conn, store.ScriptCreate, err)
	}
	script := store.ScriptGetUser
	p, err = c.GetUser(ctx, conn, in.Email)
	if errors.Is(err, customdb.ErrNoScript) || (err == nil && p == nil) {
		script = store.ScriptLogin
		p, err = c.Login(ctx, conn, in.Email, password)
	}
	if err != nil {
		return "", h.scriptFail(r, conn, script, err)
	}
	return p.UserID, nil
}

// scriptFail logs a custom database script failure (masked) and maps it to
// Auth0's error: a user_exists ValidationError is the duplicate-user 409,
// any other error the script raised is 400 auth0_idp_error with its
// message, and a script that could not run is 503.
func (h *Handlers) scriptFail(r *http.Request, conn *store.Connection, script string, err error) error {
	var red *customdb.Redactor
	if h.Scripts != nil {
		red = h.Scripts.Redactor(conn)
	} else {
		red = &customdb.Redactor{}
	}
	var se *customdb.ScriptError
	kind, msg := "error", ""
	if errors.As(err, &se) {
		kind, msg = se.Kind, red.RedactLine(se.Message)
	}
	h.log().ErrorContext(r.Context(), "management API: custom database script failed",
		"connection", conn.Name, "script", script, "kind", kind, "err", red.RedactError(err))
	switch {
	case se != nil && se.Kind == customdb.KindValidation && se.Code == "user_exists":
		return errUserExists
	case se != nil:
		return &Error{Status: http.StatusBadRequest, Code: "auth0_idp_error", Message: cmp.Or(msg, "The custom database script failed")}
	case errors.Is(err, customdb.ErrUnavailable), errors.Is(err, customdb.ErrTimeout):
		return errScriptRuntime
	case errors.Is(err, customdb.ErrNoScript):
		return &Error{Status: http.StatusBadRequest, Code: "auth0_idp_error", Message: "The connection has no " + script + " script"}
	}
	return internalError(h, r, "run "+script+" script", red.RedactError(err))
}

// userConnection is the database connection of u's own identity on name,
// or of its first own database identity when name is empty, with that
// identity. Linked identities (D-0043) are never chosen: a connection where
// u has only a linked identity is refused as one where it has none.
func (h *Handlers) userConnection(r *http.Request, u *store.User, name string) (*store.Connection, *store.Identity, error) {
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Linked() || id.Provider != store.StrategyDatabase || (name != "" && id.Connection != name) {
			continue
		}
		conn, err := h.Store.Connections().GetByName(r.Context(), u.TenantID, id.Connection)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, errUserConnection
		}
		if err != nil {
			return nil, nil, internalError(h, r, "load user connection", err)
		}
		return conn, id, nil
	}
	if name != "" {
		return nil, nil, errUserConnection
	}
	return nil, nil, errNoDatabaseIdentity
}

// loginTaken reports whether a user other than self has login (email or
// username) on conn.
func (h *Handlers) loginTaken(r *http.Request, conn *store.Connection, self, login string) error {
	other, err := h.Store.Users().FindByLogin(r.Context(), conn.TenantID, conn.Name, login)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return internalError(h, r, "update user", err)
	case other.UserID != self:
		return errUserExists
	}
	return nil
}

// UpdateUser changes the fields the body names (U3). Every check, the
// conflict check included, runs before a custom database script or the
// store write, so a refused request changes nothing.
func (h *Handlers) UpdateUser(w http.ResponseWriter, r *http.Request, id string) {
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	_, hasApp := body["app_metadata"]
	if hasApp && !callerHas(r, "update:users_app_metadata") {
		Fail(w, insufficientScope("update:users_app_metadata"))
		return
	}
	if (len(body) > 1 || !hasApp) && !callerHas(r, "update:users") {
		Fail(w, insufficientScope("update:users"))
		return
	}
	if err := checkBodyText(body); err != nil {
		Fail(w, err)
		return
	}
	in, clientID, err := readPatchBody(body)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx := r.Context()
	u, err := h.getUser(r, id)
	if err != nil {
		Fail(w, err)
		return
	}
	if err := federation.RequireMicrosoftUser(ctx, h.Store, u); err != nil {
		h.failTx(w, r, "update user", err)
		return
	}
	conn, _, err := h.userConnection(r, u, in.Connection)
	if err != nil {
		Fail(w, err)
		return
	}
	if errs := userrules.CheckPatch(conn, u, in); len(errs) > 0 {
		Fail(w, fieldError(errs[0]))
		return
	}
	next := *u
	userrules.ApplyPatch(&next, in)
	emailChanged := next.Email != u.Email
	if emailChanged {
		if err := h.loginTaken(r, conn, u.UserID, next.Email); err != nil {
			Fail(w, err)
			return
		}
	}
	if next.Username != u.Username && next.Username != "" {
		if err := h.loginTaken(r, conn, u.UserID, next.Username); err != nil {
			Fail(w, err)
			return
		}
	}
	legacy := identity.IsLegacy(conn)
	var password, hash string
	if in.Password != nil {
		history, err := identity.LoadHistory(ctx, h.Store, conn, u.UserID)
		if err != nil {
			Fail(w, internalError(h, r, "update user", err))
			return
		}
		if err := identity.CheckPassword(conn, identity.PersonOf(&next), *in.Password, history); errors.Is(err, identity.ErrPasswordInHistory) {
			Fail(w, errPasswordInHistory)
			return
		} else if err != nil {
			Fail(w, errWeakPassword)
			return
		}
		password = identity.EffectivePassword(conn, *in.Password)
		if err := h.checkPassword(r, resolved(r), "pre-change-password", password); err != nil {
			Fail(w, err)
			return
		}
		if !legacy {
			if hash, err = secrets.Hash(password); err != nil {
				Fail(w, internalError(h, r, "update user", err))
				return
			}
		}
	}
	if legacy {
		if err := h.legacyPatch(r, conn, u, &next, emailChanged, in.Password != nil, password); err != nil {
			Fail(w, err)
			return
		}
	}
	now := h.now()
	var out *store.User
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Users().GetForUpdate(ctx, u.TenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errUserNotFound
		}
		if err != nil {
			return err
		}
		if err := federation.RequireMicrosoftUser(ctx, tx, cur); err != nil {
			return err
		}
		if in.Blocked != nil && *in.Blocked {
			if last, err := lastOperator(ctx, tx, resolved(r), id); err != nil {
				return err
			} else if last {
				return errLastOperatorBlock
			}
		}
		userrules.ApplyPatch(cur, in)
		cur.UpdatedAt = now
		if in.Password != nil {
			cur.LastPasswordReset = &now
		}
		if err := tx.Users().Update(ctx, cur); errors.Is(err, store.ErrConflict) {
			return errUserExists
		} else if err != nil {
			return err
		}
		// Links sent to the old address must not verify the new one: drop
		// the open verification tickets, and the unused reset tickets
		// (one with mark_email_as_verified would verify it).
		if emailChanged {
			if _, err := tx.EmailVerificationTickets().DeleteByUser(ctx, u.TenantID, id); err != nil {
				return err
			}
			if _, err := tx.PasswordResetTickets().DeleteByUser(ctx, u.TenantID, id); err != nil {
				return err
			}
		}
		if in.Password != nil {
			if legacy {
				if err := h.database(tx).RecordLegacyPassword(ctx, conn, id, password); err != nil {
					return err
				}
			} else {
				if err := tx.Users().SetPasswordHash(ctx, u.TenantID, id, conn.Name, hash, now); err != nil {
					return err
				}
				if err := identity.RecordPassword(ctx, tx, conn, id, hash); err != nil {
					return err
				}
			}
		}
		if out, err = tx.Users().Get(ctx, u.TenantID, id); err != nil || in.Password == nil {
			return err
		}
		res, _ := tenant.FromContext(ctx)
		return actions.PasswordChanged(ctx, tx, h.Actions, res, out, conn, actions.RequestInfo{IP: httpx.ClientIP(r, h.TrustProxyHeaders),
			Hostname: res.Host, Origin: res.Origin(), Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language")})
	})
	if err != nil {
		h.failTx(w, r, "update user", err)
		return
	}
	h.audit(r, "update user", "user_id", id, "fields", strings.Join(slices.Sorted(maps.Keys(body)), ","))
	if (in.VerifyEmail != nil && *in.VerifyEmail) || (in.VerifyEmail == nil && emailChanged && !out.EmailVerified) {
		h.sendVerification(r, out, clientID)
	}
	writeJSON(w, http.StatusOK, UserJSON(out))
}

// legacyPatch runs change_email or change_password on a legacy connection.
// CheckPatch refuses both in one request.
func (h *Handlers) legacyPatch(r *http.Request, conn *store.Connection, u, next *store.User, emailChanged, passwordChanged bool, password string) error {
	if !emailChanged && !passwordChanged {
		return nil
	}
	script := store.ScriptChangeEmail
	if passwordChanged {
		script = store.ScriptChangePassword
	}
	if h.Scripts == nil {
		return h.scriptFail(r, conn, script, customdb.ErrUnavailable)
	}
	var ok bool
	var err error
	if emailChanged {
		ok, err = h.Scripts.ChangeEmail(r.Context(), conn, u.Email, next.Email, next.EmailVerified)
	} else {
		ok, err = h.Scripts.ChangePassword(r.Context(), conn, u.Email, password)
	}
	if err != nil {
		return h.scriptFail(r, conn, script, err)
	}
	if !ok {
		h.log().WarnContext(r.Context(), "management API: custom database script made no change", "connection", conn.Name, "script", script, "user_id", u.UserID)
		return &Error{Status: http.StatusBadRequest, Code: "auth0_idp_error", Message: "The custom database script did not make the change"}
	}
	return nil
}

// DeleteUser deletes a user with everything that names it (U12). An
// unknown well-formed ID answers 204 too.
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	ctx := r.Context()
	tn := resolved(r)
	u, err := h.Store.Users().Get(ctx, tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "delete user", err))
		return
	}
	if err := federation.RequireMicrosoftUser(ctx, h.Store, u); err != nil {
		h.failTx(w, r, "delete user", err)
		return
	}
	// Refuse before a script deletes the user from a legacy store; the
	// transaction below checks again under the user's lock.
	if last, err := lastOperator(ctx, h.Store, tn, id); err != nil {
		Fail(w, internalError(h, r, "delete user", err))
		return
	} else if last {
		Fail(w, errLastOperatorRemove)
		return
	}
	conn, ident, err := h.userConnection(r, u, "")
	switch {
	case errors.Is(err, errUserConnection), errors.Is(err, errNoDatabaseIdentity):
		// No connection to run a script on: delete the local record.
	case err != nil:
		Fail(w, err)
		return
	case identity.IsLegacy(conn):
		if h.Scripts == nil {
			Fail(w, h.scriptFail(r, conn, store.ScriptDelete, customdb.ErrUnavailable))
			return
		}
		if err := h.Scripts.Delete(ctx, conn, ident.UserID); err != nil {
			Fail(w, h.scriptFail(r, conn, store.ScriptDelete, err))
			return
		}
	}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Users().GetForUpdate(ctx, tn.ID, id)
		if err != nil {
			return err
		}
		if err := federation.RequireMicrosoftUser(ctx, tx, cur); err != nil {
			return err
		}
		if last, err := lastOperator(ctx, tx, tn, id); err != nil {
			return err
		} else if last {
			return errLastOperatorRemove
		}
		return tx.Users().Delete(ctx, tn.ID, id)
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.failTx(w, r, "delete user", err)
		return
	}
	h.audit(r, "delete user", "user_id", id)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) checkPassword(r *http.Request, tenant *store.Tenant, stage, password string) error {
	svc := h.Protection
	if svc == nil {
		svc = &protection.Service{Store: h.Store, Log: h.log(), Now: h.now}
	}
	err := svc.CheckPassword(r.Context(), tenant, stage, password)
	if errors.Is(err, protection.ErrPasswordLeaked) {
		return &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: protection.ErrPasswordLeaked.Error()}
	}
	if err != nil {
		return &Error{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Message: protection.ErrBreachUnavailable.Error()}
	}
	return nil
}

// ListUserOrganizations lists the organizations a user is a member of, in
// the organization list shapes.
func (h *Handlers) ListUserOrganizations(w http.ResponseWriter, r *http.Request, userID string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	p, checkpoint, err := orgQuery(r, "page", "per_page", "include_totals", "from", "take")
	if err != nil {
		Fail(w, err)
		return
	}
	res, err := orgs.UserOrganizations(r.Context(), resolved(r).ID, userID, p)
	switch {
	case errors.Is(err, store.ErrNotFound):
		err = errUserNotFound
	case errors.Is(err, store.ErrInvalid):
		err = errOrgCursor
	}
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, o := range res.Items {
		items = append(items, orgView(o))
	}
	writeOrgList(w, "organizations", items, res.Total, res.Next, p, checkpoint, false)
}
