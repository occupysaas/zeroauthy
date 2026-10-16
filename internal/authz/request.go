package authz

import (
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
	for _, n := range strictUnsupported {
		if q.Has(n) {
			r.Present = append(r.Present, n)
		}
	}
	return r
}

// Params flattens r for storage in a login transaction.
func (r Request) Params() map[string]string {
	out := map[string]string{}
	for _, name := range paramNames {
		if v := *r.field(name); v != "" {
			out[name] = v
		}
	}
	return out
}

// RequestFromParams is the inverse of Params.
func RequestFromParams(p map[string]string) Request {
	var r Request
	for _, name := range paramNames {
		*r.field(name) = p[name]
	}
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
