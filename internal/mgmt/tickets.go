package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// maxTicketTTL bounds ttl_sec. Auth0 accepts very large values (U6); this
// only keeps the expiry representable.
const maxTicketTTL = math.MaxInt32

var (
	errResultURLWithClient = badBodyRaw("result_url cannot be used together with client_id")
	errTicketNoEmail       = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The user does not have an email address."}
)

// ttlMinimumMessage is Auth0's message for a negative ttl_sec (U6), with
// the value given.
const ttlMinimumMessage = "Payload validation error: 'Value %s is less than minimum 0' on property ttl_sec (Number of seconds for which the ticket is valid before expiration. If unspecified or set to 0, this value defaults to 432000 seconds (5 days))."

func missingProperty(k string) *Error {
	return badBodyRaw(fmt.Sprintf("Payload validation error: 'Missing required property: %s'.", k))
}

// ticketIdentity is the optional identity of a ticket body.
type ticketIdentity struct{ UserID, Provider string }

// ticketBody is a POST /tickets/* body.
type ticketBody struct {
	resultURL, userID, clientID, connectionID, email string
	ttl                                              int64
	markVerified, includeEmail                       bool
	identity                                         *ticketIdentity
}

// readTicketBody reads a ticket body whose properties are among allowed.
// Unknown properties and wrong types are 400 invalid_body.
func readTicketBody(body map[string]json.RawMessage, allowed ...string) (*ticketBody, error) {
	if err := checkBodyText(body); err != nil {
		return nil, err
	}
	b := userBody{body}
	in := &ticketBody{}
	strs := map[string]*string{"result_url": &in.resultURL, "user_id": &in.userID, "client_id": &in.clientID,
		"connection_id": &in.connectionID, "email": &in.email}
	bools := map[string]*bool{"mark_email_as_verified": &in.markVerified, "includeEmailInRedirect": &in.includeEmail}
	for _, k := range slices.Sorted(maps.Keys(body)) {
		if !slices.Contains(allowed, k) {
			return nil, badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s'.", k))
		}
		var err error
		switch {
		case strs[k] != nil:
			*strs[k], err = b.str(k)
		case bools[k] != nil:
			var v *bool
			if v, err = b.boolPtr(k); err == nil {
				*bools[k] = *v
			}
		case k == "ttl_sec":
			in.ttl, err = readTTL(body[k])
		case k == "identity":
			in.identity, err = readTicketIdentity(body[k])
		}
		if err != nil {
			return nil, err
		}
	}
	if in.resultURL != "" {
		if u, err := url.Parse(in.resultURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, badBodyRaw(fmt.Sprintf("Payload validation error: 'Object didn't pass validation for format absolute-uri: %s' on property result_url.", in.resultURL))
		}
		if in.clientID != "" {
			return nil, errResultURLWithClient
		}
	}
	return in, nil
}

// readTTL reads ttl_sec: a whole number, at least 0. Values above
// maxTicketTTL are clamped to it.
func readTTL(raw json.RawMessage) (int64, error) {
	var n json.Number
	if isNull(raw) || json.Unmarshal(raw, &n) != nil {
		return 0, wrongType("ttl_sec", "integer", raw)
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) {
		return 0, wrongType("ttl_sec", "integer", raw)
	}
	if f < 0 {
		return 0, badBodyRaw(fmt.Sprintf(ttlMinimumMessage, n.String()))
	}
	return int64(min(f, maxTicketTTL)), nil
}

func readTicketIdentity(raw json.RawMessage) (*ticketIdentity, error) {
	var v map[string]json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &v) != nil {
		return nil, wrongType("identity", "object", raw)
	}
	id := &ticketIdentity{}
	b := userBody{v}
	for _, k := range slices.Sorted(maps.Keys(v)) {
		var err error
		switch k {
		case "user_id":
			id.UserID, err = b.str(k)
		case "provider":
			id.Provider, err = b.str(k)
		default:
			err = badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s' on property identity.", k))
		}
		if err != nil {
			return nil, err
		}
	}
	switch {
	case id.UserID == "":
		return nil, badBodyRaw("Payload validation error: 'Missing required property: user_id' on property identity.")
	case id.Provider == "":
		return nil, badBodyRaw("Payload validation error: 'Missing required property: provider' on property identity.")
	}
	return id, nil
}

// lifetime is the ticket's lifetime: ttl_sec, or 432000 s when 0.
func (in *ticketBody) lifetime() time.Duration {
	if in.ttl == 0 {
		return dbconn.VerificationTicketLifetime
	}
	return time.Duration(in.ttl) * time.Second
}

// ticketUser loads the user a ticket is for.
func (h *Handlers) ticketUser(r *http.Request, userID string) (*store.User, error) {
	if !validUserID(userID) {
		return nil, errUserNotFound
	}
	u, err := h.Store.Users().Get(r.Context(), resolved(r).ID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(h, r, "load user", err)
	}
	return u, nil
}

// ticketIdentityOf returns the user's identity named by id, or nil when
// id is nil; an identity the user does not have is 400 invalid_body.
func ticketIdentityOf(u *store.User, id *ticketIdentity) (*store.Identity, error) {
	if id == nil {
		return nil, nil
	}
	for i := range u.Identities {
		if u.Identities[i].Provider == id.Provider && u.Identities[i].UserID == id.UserID {
			return &u.Identities[i], nil
		}
	}
	return nil, badBodyRaw("Payload validation error: the user has no identity " + id.Provider + "|" + id.UserID + ".")
}

// checkTicketClient checks that client_id, when given, names an
// application of the tenant.
func (h *Handlers) checkTicketClient(r *http.Request, clientID string) error {
	if clientID == "" {
		return nil
	}
	_, err := h.Store.Clients().Get(r.Context(), resolved(r).ID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return errClientNotFound
	}
	if err != nil {
		return internalError(h, r, "load client", err)
	}
	return nil
}

// passwordChangeTarget finds the user and database connection of a
// password-change ticket: by user_id, or by email on connection_id.
func (h *Handlers) passwordChangeTarget(r *http.Request, in *ticketBody) (*store.User, string, error) {
	ctx, tn := r.Context(), resolved(r)
	if in.userID != "" {
		u, err := h.ticketUser(r, in.userID)
		if err != nil {
			return nil, "", err
		}
		id, err := ticketIdentityOf(u, in.identity)
		if err != nil {
			return nil, "", err
		}
		// A linked identity's password is not the user's to reset: the
		// ticket could never be used, as userConnection skips it too.
		if id != nil {
			if id.Linked() || id.Provider != store.StrategyDatabase {
				return nil, "", errNoDatabaseIdentity
			}
			return u, id.Connection, nil
		}
		for _, id := range u.Identities {
			if !id.Linked() && id.Provider == store.StrategyDatabase {
				return u, id.Connection, nil
			}
		}
		return nil, "", errNoDatabaseIdentity
	}
	switch {
	case in.email == "":
		return nil, "", missingProperty("email")
	case in.connectionID == "":
		return nil, "", missingProperty("connection_id")
	}
	conn, err := h.Store.Connections().Get(ctx, tn.ID, in.connectionID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.Strategy != store.StrategyDatabase) {
		return nil, "", errUserConnection
	}
	if err != nil {
		return nil, "", internalError(h, r, "load connection", err)
	}
	users, err := h.Store.Users().FindByEmail(ctx, tn.ID, strings.ToLower(in.email))
	if err != nil {
		return nil, "", internalError(h, r, "find user", err)
	}
	for _, u := range users {
		for _, id := range u.Identities {
			if !id.Linked() && id.Provider == store.StrategyDatabase && id.Connection == conn.Name {
				return u, conn.Name, nil
			}
		}
	}
	return nil, "", errUserNotFound
}

// CustomDomainHeader selects the public domain of a new user-facing link.
const CustomDomainHeader = "auth0-custom-domain"

// notificationHost chooses the host of a new link: the auth0-custom-domain
// header (canonical or a usable domain of this tenant), else a usable
// default, else canonical. The request's own Host never decides. An
// unusable or foreign selection is 503 before anything is created.
func (h *Handlers) notificationHost(r *http.Request) (string, error) {
	host, err := customdomain.SelectNotificationOrigin(r.Context(), h.Store, resolved(r).ID, r.Header.Get(CustomDomainHeader))
	switch {
	case errors.Is(err, customdomain.ErrDomainUnavailable):
		return "", &Error{Status: http.StatusServiceUnavailable, Code: "custom_domain_unavailable", Message: "The selected custom domain is not available."}
	case err != nil:
		return "", internalError(h, r, "select notification domain", err)
	case host == "":
		return "", internalError(h, r, "select notification domain", errors.New("tenant has no canonical host"))
	}
	return host, nil
}

// CreatePasswordChangeTicket serves POST /tickets/password-change (U6):
// a link to the new-password form for a database user, named by user_id
// or by email and connection_id. result_url is stored, but as on Auth0
// the success page does not redirect to it; mark_email_as_verified sets
// email_verified when the password is changed.
func (h *Handlers) CreatePasswordChangeTicket(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := readTicketBody(body, "result_url", "user_id", "client_id", "connection_id", "email", "ttl_sec",
		"mark_email_as_verified", "includeEmailInRedirect", "identity")
	if err != nil {
		Fail(w, err)
		return
	}
	u, connection, err := h.passwordChangeTarget(r, in)
	if err != nil {
		Fail(w, err)
		return
	}
	if err := h.checkTicketClient(r, in.clientID); err != nil {
		Fail(w, err)
		return
	}
	host, err := h.notificationHost(r)
	if err != nil {
		Fail(w, err)
		return
	}
	raw, err := dbconn.IssueResetTicket(r.Context(), h.Store, store.PasswordResetTicket{
		Origin: "https://" + host, TenantID: u.TenantID, UserID: u.UserID, Connection: connection, ClientID: in.clientID,
		ResultURL: in.resultURL, IncludeEmailInRedirect: in.includeEmail, MarkEmailVerified: in.markVerified,
	}, dbconn.TicketTokenLength, h.now(), in.lifetime())
	if err != nil {
		Fail(w, internalError(h, r, "create password change ticket", err))
		return
	}
	h.audit(r, "create password change ticket", "user_id", u.UserID, "connection", connection, "ttl_sec", int64(in.lifetime()/time.Second))
	writeJSON(w, http.StatusCreated, map[string]string{"ticket": dbconn.PasswordChangeLink("https://"+host+"/", raw)})
}

// CreateEmailVerificationTicket serves POST /tickets/email-verification
// (U6): a link that verifies the user's email when opened.
func (h *Handlers) CreateEmailVerificationTicket(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := readTicketBody(body, "result_url", "user_id", "client_id", "ttl_sec", "includeEmailInRedirect", "identity")
	if err != nil {
		Fail(w, err)
		return
	}
	if in.userID == "" {
		Fail(w, missingProperty("user_id"))
		return
	}
	u, err := h.ticketUser(r, in.userID)
	if err != nil {
		Fail(w, err)
		return
	}
	connection := dbconn.VerificationConnection(u)
	if id, err := ticketIdentityOf(u, in.identity); err != nil {
		Fail(w, err)
		return
	} else if id != nil {
		connection = id.Connection
	}
	if u.Email == "" {
		Fail(w, errTicketNoEmail)
		return
	}
	if err := h.checkTicketClient(r, in.clientID); err != nil {
		Fail(w, err)
		return
	}
	host, err := h.notificationHost(r)
	if err != nil {
		Fail(w, err)
		return
	}
	raw, err := dbconn.IssueVerificationTicket(r.Context(), h.Store, store.EmailVerificationTicket{
		Origin: "https://" + host, TenantID: u.TenantID, UserID: u.UserID, Connection: connection, ClientID: in.clientID, Email: strings.ToLower(u.Email),
		ResultURL: in.resultURL, IncludeEmailInRedirect: in.includeEmail,
	}, h.now(), in.lifetime())
	if err != nil {
		Fail(w, internalError(h, r, "create email verification ticket", err))
		return
	}
	h.audit(r, "create email verification ticket", "user_id", u.UserID, "connection", connection, "ttl_sec", int64(in.lifetime()/time.Second))
	writeJSON(w, http.StatusCreated, map[string]string{"ticket": dbconn.VerificationLink("https://"+host+"/", raw)})
}
