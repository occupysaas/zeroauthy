package authz

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Request holds the /authorize parameters zeroauthy uses. Unknown
// parameters (such as SDK telemetry) are ignored.
type Request struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	Scope               string
	State               string
	Nonce               string
	Audience            string
	Prompt              string
	MaxAge              string
	CodeChallenge       string
	CodeChallengeMethod string
	Connection          string
	LoginHint           string
	ScreenHint          string
	Organization        string
	Invitation          string
	UILocales           string
	// Ext holds ext-* parameters, kept for Actions (sub-project 2).
	Ext map[string]string
	// Pushed is true for a request that came from /oauth/par.
	Pushed bool
	// RequestObject is the raw request parameter. Request objects are not
	// supported; it is read only to deliver request_not_supported. Not part
	// of Params().
	RequestObject string
	// Present lists which strictUnsupported parameters the request carried.
	// It is not part of Params(): a request that carries any of these never
	// reaches a transaction for a strict client.
	Present []string
}

// strictUnsupported are /authorize parameters that strict third-party
// applications may not send (D-0025). Organization and invitation are
// refused for every client until Organizations exist.
var strictUnsupported = []string{"claims", "id_token_hint", "login_ticket", "request", "request_uri", "screen_hint"}

// paramNames maps query parameter names to Request fields; it drives
// parsing and the transaction round trip.
var paramNames = []string{
	"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
	"audience", "prompt", "max_age", "code_challenge", "code_challenge_method",
	"connection", "login_hint", "screen_hint", "organization", "invitation", "ui_locales",
}

func (r *Request) field(name string) *string {
	switch name {
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

// requestObjectDelivery reads state and response_mode from an unverified
// request object, for delivering request_not_supported only (OpenID
// Connect Core §6.1: its values take precedence over the query). It
// returns empty strings for anything that is not a readable JWS.
func requestObjectDelivery(raw string) (state, responseMode string) {
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
	r.Pushed = p[pushedKey] == "1"
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
