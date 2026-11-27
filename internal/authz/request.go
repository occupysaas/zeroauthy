package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Request holds the /authorize parameters zeroauthy uses. Unknown
// parameters (such as SDK telemetry) are ignored.
type Request struct {
	// SAML is the server-only SAML IdP binding (Plan 37a, internal/samlidp),
	// persisted under store.TxnParamSAML; ParseRequest never reads it.
	SAML                  string
	Resources             []string
	OptionalRedirectURI   bool // Server-only compatibility switch.
	ACRValues             string
	Claims                string
	IgnoreClaimsParameter bool // Server-only; never read from request parameters.
	DPoPJKT               string
	ClientID              string
	RedirectURI           string
	ResponseType          string
	ResponseMode          string
	Scope                 string
	State                 string
	Nonce                 string
	Audience              string
	Prompt                string
	MaxAge                string
	CodeChallenge         string
	CodeChallengeMethod   string
	Connection            string
	LoginHint             string
	ScreenHint            string
	Organization          string
	Invitation            string
	invitationBinding     map[string]string
	UILocales             string
	// OrgID and OrgMode bind the resolved organization (spec §5.1). They
	// are stored under store.TxnParamOrgID and store.TxnParamOrgMode;
	// ParseRequest never reads them, so a client cannot set them.
	OrgID   string
	OrgMode OrgMode
	// Ext holds ext-* parameters, kept for Actions (sub-project 2).
	Ext map[string]string
	// Pushed is true for a request that came from /oauth/par.
	Pushed bool
	// Signed is true when the parameters came from a verified signed request
	// object, at /authorize or in the pushed request (JAR, spec §4). It is
	// stored under signedKey; ParseRequest never sets it.
	Signed bool
	// RequestObject is the raw request parameter, until ApplyRequestObject
	// merges a verified object. Never part of Params() or a log.
	RequestObject string
	// objectErr is ApplyRequestObject's failure. ValidateRequest delivers it
	// only to the query's registered redirect_uri, never one from the object.
	objectErr *Error
	// Present lists which strictUnsupported parameters the request carried.
	// It is not part of Params(): a request that carries any of these never
	// reaches a transaction for a strict client.
	Present []string
}

// strictUnsupported are /authorize parameters that strict third-party
// applications may not send (D-0025).
var strictUnsupported = []string{"claims", "id_token_hint", "login_ticket", "request", "request_uri", "screen_hint"}

// paramNames maps query parameter names to Request fields; it drives
// parsing and the transaction round trip.
var paramNames = []string{
	"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
	"acr_values", "claims", "dpop_jkt", "audience", "prompt", "max_age", "code_challenge", "code_challenge_method",
	"connection", "login_hint", "screen_hint", "organization", "invitation", "ui_locales",
}

func (r *Request) field(name string) *string {
	switch name {
	case "acr_values":
		return &r.ACRValues
	case "claims":
		return &r.Claims
	case "client_id":
		return &r.ClientID
	case "redirect_uri":
		return &r.RedirectURI
	case "response_type":
		return &r.ResponseType
	case "response_mode":
		return &r.ResponseMode
	case "scope":
		return &r.Scope
	case "state":
		return &r.State
	case "dpop_jkt":
		return &r.DPoPJKT
	case "nonce":
		return &r.Nonce
	case "audience":
		return &r.Audience
	case "prompt":
		return &r.Prompt
	case "max_age":
		return &r.MaxAge
	case "code_challenge":
		return &r.CodeChallenge
	case "code_challenge_method":
		return &r.CodeChallengeMethod
	case "connection":
		return &r.Connection
	case "login_hint":
		return &r.LoginHint
	case "screen_hint":
		return &r.ScreenHint
	case "organization":
		return &r.Organization
	case "invitation":
		return &r.Invitation
	case "ui_locales":
		return &r.UILocales
	}
	panic("authz: unknown parameter " + name)
}

// ParseRequest reads /authorize query parameters.
func ParseRequest(q url.Values) Request {
	var r Request
	r.Resources = slices.Clone(q["resource"])
	for _, name := range paramNames {
		*r.field(name) = q.Get(name)
	}
	r.RequestObject = q.Get("request")
	for _, n := range strictUnsupported {
		if q.Has(n) {
			r.Present = append(r.Present, n)
		}
	}
	for k := range q {
		if strings.HasPrefix(k, ExtPrefix) {
			if r.Ext == nil {
				r.Ext = map[string]string{}
			}
			r.Ext[k] = q.Get(k)
		}
	}
	return r
}

// maxRequestObjectBytes bounds a request parameter before it is parsed.
const maxRequestObjectBytes = 16 << 10

// signedKey marks a request whose parameters came from a verified signed
// request object in stored Params. Like pushedKey it is not a request
// parameter: ParseRequest never reads it.
const signedKey = "za_signed"

// ApplyRequestObject processes the request parameter of an authorization
// request (JAR, RFC 9101; spec §4) before ValidateRequest. A signed object
// from req.ClientID's signed_request_object credentials is verified, its
// parameters replace the query's, and req.Signed is set; ValidateRequest then
// checks the merged request, redirect_uri registration included.
//
// Nothing changes, and ValidateRequest keeps D-0035's request_not_supported
// (or D-0025 for strict clients), when the store lacks client_credentials.v1,
// the object is unsigned (alg none, LR35-4), or the client is unknown or
// strict. A failed verification returns invalid_request_object (or
// server_error) and records it on req, so that /authorize delivers it only to
// the query's registered redirect_uri. Log lines carry the reason, never the
// object.
func ApplyRequestObject(ctx context.Context, st store.Store, t *store.Tenant, issuer string, now time.Time, log *slog.Logger, req *Request) *Error {
	if !slices.Contains(req.Present, "request") || req.ClientID == "" || !store.ClientCredentialsAvailable(ctx, st) {
		return nil
	}
	fail := func(e *Error) *Error {
		req.objectErr = e
		return e
	}
	client, err := st.Clients().Get(ctx, t.ID, req.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		log.ErrorContext(ctx, "load client", "tenant", t.ID, "client_id", req.ClientID, "err", err)
		return fail(errServer())
	}
	if access.Strict(client) {
		return nil
	}
	raw := req.RequestObject
	if len(raw) > maxRequestObjectBytes {
		log.InfoContext(ctx, "request object refused: too long", "tenant", t.ID, "client_id", client.ClientID)
		return fail(errInvalidRequestObject())
	}
	if unsignedObject(raw) {
		return nil
	}
	var creds []*store.ClientCredential
	if sro := client.SignedRequestObject; sro != nil && len(sro.Credentials) > 0 {
		all, err := st.ClientCredentials().List(ctx, t.ID, client.ClientID)
		if err != nil {
			log.ErrorContext(ctx, "load client credentials", "tenant", t.ID, "client_id", client.ClientID, "err", err)
			return fail(errServer())
		}
		// Only the signed_request_object credentials: never one enabled
		// only for private_key_jwt.
		for _, c := range all {
			if c.ClientID == client.ClientID && slices.Contains(sro.Credentials, c.ID) {
				creds = append(creds, c)
			}
		}
	}
	inner, err := verifyRequestObject(raw, client, creds, issuer, now, func(jti string, exp time.Time) error {
		return st.ClientCredentials().UseJTI(ctx, t.ID, client.ClientID, jti, exp)
	})
	if err != nil {
		log.InfoContext(ctx, "request object refused", "tenant", t.ID, "client_id", client.ClientID, "reason", err.Error())
		return fail(errInvalidRequestObject())
	}
	// Parameters inside the object take precedence over the query.
	if inner.Has("resource") {
		req.Resources = slices.Clone(inner["resource"])
	}
	for _, name := range paramNames {
		if name != "client_id" && inner.Has(name) {
			*req.field(name) = inner.Get(name)
		}
	}
	for k := range inner {
		if strings.HasPrefix(k, ExtPrefix) {
			if req.Ext == nil {
				req.Ext = map[string]string{}
			}
			req.Ext[k] = inner.Get(k)
		}
	}
	req.Signed, req.RequestObject = true, ""
	req.Present = slices.DeleteFunc(slices.Clone(req.Present), func(n string) bool { return n == "request" })
	return nil
}

// requestObjectClaims are JWT claims, not authorization parameters.
var requestObjectClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id"}

// verifyRequestObject verifies raw with creds (clientcred.Verify, Purpose
// RequestObject: iss, aud = issuer, exp, nbf, iat, the 60 minute lifetime
// and a single-use jti) and checks that its client_id is c's. It returns the
// object's authorization parameters; objects and arrays are dropped. The
// error names the reason and never contains raw.
func verifyRequestObject(raw string, c *store.Client, creds []*store.ClientCredential, issuer string, now time.Time, useJTI func(string, time.Time) error) (url.Values, error) {
	claims, err := clientcred.Verify(clientcred.VerifyInput{
		Raw: raw, ClientID: c.ClientID, Audiences: []string{issuer}, Purpose: clientcred.RequestObject,
		Credentials: creds, Now: now, UseJTI: useJTI,
	})
	if err != nil {
		return nil, err
	}
	if id, _ := claims["client_id"].(string); id != c.ClientID {
		return nil, errors.New("client_id does not match the client")
	}
	// RFC 9101 §4: an object never nests another.
	if _, ok := claims["request"]; ok {
		return nil, errors.New("request inside the request object")
	}
	if _, ok := claims["request_uri"]; ok {
		return nil, errors.New("request_uri inside the request object")
	}
	out := url.Values{}
	for k, v := range claims {
		if slices.Contains(requestObjectClaims, k) {
			continue
		}
		if k == "resource" {
			if array, ok := v.([]any); ok {
				if len(array) == 0 {
					out.Set(k, "")
					continue
				}
				for _, item := range array {
					value, ok := item.(string)
					if !ok {
						return nil, errors.New("invalid resource array")
					}
					out.Add(k, value)
				}
				continue
			}
		}
		if k == "claims" {
			if _, isString := v.(string); !isString {
				data, err := json.Marshal(v)
				if err != nil {
					return nil, errors.New("invalid claims object")
				}
				out.Set(k, string(data))
				continue
			}
		}
		switch v := v.(type) {
		case string:
			out.Set(k, v)
		case float64:
			out.Set(k, strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			out.Set(k, strconv.FormatBool(v))
		}
	}
	return out, nil
}

// unsignedObject reports whether raw is a compact JWT whose header alg is
// none (LR35-4).
func unsignedObject(raw string) bool {
	head, _, ok := strings.Cut(raw, ".")
	if !ok {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	return json.Unmarshal(b, &h) == nil && strings.EqualFold(h.Alg, "none")
}

// unsignedObjectDelivery reads state and response_mode from a request
// object that is not processed (unsigned, or JAR unavailable), for
// delivering request_not_supported only (D-0035; OpenID Connect Core §6.1:
// its values take precedence over the query). It returns empty strings for
// anything that is not a readable JWS.
func unsignedObjectDelivery(raw string) (state, responseMode string) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c map[string]any
	if json.Unmarshal(payload, &c) != nil {
		return "", ""
	}
	state, _ = c["state"].(string)
	responseMode, _ = c["response_mode"].(string)
	return state, responseMode
}

// Params flattens r for storage in a login transaction.
func (r Request) Params() map[string]string {
	out := map[string]string{}
	if len(r.Resources) == 1 {
		out["resource"] = r.Resources[0]
	}
	for _, name := range paramNames {
		if v := *r.field(name); v != "" {
			out[name] = v
		}
	}
	for k, v := range r.Ext {
		out[k] = v
	}
	if r.Pushed {
		out[pushedKey] = "1"
	}
	if r.Signed {
		out[signedKey] = "1"
	}
	if r.OrgID != "" {
		out[store.TxnParamOrgID] = r.OrgID
	}
	if r.SAML != "" {
		out[store.TxnParamSAML] = r.SAML
	}
	if r.OrgMode != OrgNone {
		out[store.TxnParamOrgMode] = string(r.OrgMode)
	}
	for _, k := range []string{"za_invitation_id", "za_invitation_client", "za_invitation_connection"} {
		if v := r.invitationBinding[k]; v != "" {
			out[k] = v
		}
	}
	if out["za_invitation_id"] != "" {
		delete(out, "invitation")
	}
	return out
}

// RequestFromParams is the inverse of Params.
func RequestFromParams(p map[string]string) Request {
	var r Request
	for _, name := range paramNames {
		*r.field(name) = p[name]
	}
	for k, v := range p {
		if strings.HasPrefix(k, ExtPrefix) {
			if r.Ext == nil {
				r.Ext = map[string]string{}
			}
			r.Ext[k] = v
		}
	}
	for _, k := range []string{"za_invitation_id", "za_invitation_client", "za_invitation_connection"} {
		if p[k] != "" {
			if r.invitationBinding == nil {
				r.invitationBinding = map[string]string{}
			}
			r.invitationBinding[k] = p[k]
		}
	}
	r.Pushed = p[pushedKey] == "1"
	r.Signed = p[signedKey] == "1"
	r.OrgID, r.OrgMode = p[store.TxnParamOrgID], OrgMode(p[store.TxnParamOrgMode])
	r.SAML = p[store.TxnParamSAML]
	return r
}

func (r Request) Scopes() []string  { return strings.Fields(r.Scope) }
func (r Request) Prompts() []string { return strings.Fields(r.Prompt) }

// MaxAgeSeconds returns max_age and whether it was set.
func (r Request) MaxAgeSeconds() (int, bool) {
	if r.MaxAge == "" {
		return 0, false
	}
	n, err := strconv.Atoi(r.MaxAge)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// VerifySignedRequestObject verifies raw, a signed request object (JAR)
// sent by client c outside /authorize (/bc-authorize, Plan 41c), with c's
// signed_request_object credentials, and returns its parameters. Unsigned
// objects and failures are errors whose text never contains raw.
func VerifySignedRequestObject(ctx context.Context, st store.Store, t *store.Tenant, issuer string, now time.Time, c *store.Client, raw string) (url.Values, error) {
	if len(raw) > maxRequestObjectBytes {
		return nil, errors.New("request object too long")
	}
	if unsignedObject(raw) || !store.ClientCredentialsAvailable(ctx, st) {
		return nil, errors.New("request object must be signed")
	}
	var creds []*store.ClientCredential
	if sro := c.SignedRequestObject; sro != nil && len(sro.Credentials) > 0 {
		all, err := st.ClientCredentials().List(ctx, t.ID, c.ClientID)
		if err != nil {
			return nil, err
		}
		for _, cr := range all {
			if cr.ClientID == c.ClientID && slices.Contains(sro.Credentials, cr.ID) {
				creds = append(creds, cr)
			}
		}
	}
	return verifyRequestObject(raw, c, creds, issuer, now, func(jti string, exp time.Time) error {
		return st.ClientCredentials().UseJTI(ctx, t.ID, c.ClientID, jti, exp)
	})
}
