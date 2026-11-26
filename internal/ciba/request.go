// Package ciba validates OpenID Client-Initiated Backchannel
// Authentication requests (poll mode) as Auth0 documents them (Plan 41c,
// D-0100).
package ciba

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits (D-0100).
const (
	// DefaultExpiry is Auth0's default requested_expiry.
	DefaultExpiry = 300
	// MinEmailExpiry and MaxExpiry bound the email channel (LR41c-6).
	MinEmailExpiry = 301
	MaxExpiry      = 259200
	// Interval is the minimum poll interval in seconds.
	Interval = 5
	// MaxBindingMessage is Auth0's binding_message length limit.
	MaxBindingMessage = 64
	maxLoginHint      = 2048
)

// GrantType is the CIBA token grant.
const GrantType = "urn:openid:params:grant-type:ciba"

// bindingMessage is Auth0's documented alphabet: letters, digits and +-_.,:# (LR41c-4).
var bindingMessage = regexp.MustCompile(`^[A-Za-z0-9+\-_.,:#]{1,64}$`)

// Error is a CIBA Core error for /bc-authorize.
type Error struct{ Code, Description string }

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func invalid(format string, args ...any) *Error {
	return &Error{"invalid_request", fmt.Sprintf(format, args...)}
}

// Request is a validated backchannel authentication request.
type Request struct {
	Scopes         []string
	Audience       string
	UserID         string
	BindingMessage string
	// Expiry is the request lifetime in seconds.
	Expiry int
}

// Lifetime is Expiry as a duration.
func (r Request) Lifetime() time.Duration { return time.Duration(r.Expiry) * time.Second }

// Parse validates form for a tenant whose issuer (as the request's host
// presents it) is issuer. Client authentication and a signed request
// object are the caller's; form holds the merged parameters.
func Parse(form url.Values, issuer string) (Request, *Error) {
	var r Request
	for _, refused := range []string{"id_token_hint", "login_hint_token"} {
		if form.Has(refused) {
			return r, invalid("%s is not supported; use login_hint", refused)
		}
	}
	if form.Has("authorization_details") {
		return r, invalid("authorization_details is not supported") // LR41c-3
	}
	if form.Has("user_code") {
		return r, invalid("user_code is not supported")
	}
	r.Scopes = strings.Fields(form.Get("scope"))
	if !slices.Contains(r.Scopes, "openid") {
		return r, &Error{"invalid_scope", "scope must include openid"}
	}
	raw := form.Get("login_hint")
	if raw == "" {
		return r, invalid("login_hint is required")
	}
	if len(raw) > maxLoginHint {
		return r, invalid("login_hint is too long")
	}
	var h struct {
		Format string `json:"format"`
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
	}
	if json.Unmarshal([]byte(raw), &h) != nil || h.Format != "iss_sub" || h.Sub == "" {
		return r, invalid(`login_hint must be {"format":"iss_sub","iss":"<issuer>","sub":"<user_id>"}`)
	}
	if h.Iss != issuer {
		return r, invalid("login_hint iss must be this tenant's issuer")
	}
	r.UserID = h.Sub
	r.BindingMessage = form.Get("binding_message")
	if r.BindingMessage == "" {
		return r, invalid("binding_message is required")
	}
	if !bindingMessage.MatchString(r.BindingMessage) {
		return r, invalid("binding_message must be 1 to %d letters, digits or +-_.,:# characters", MaxBindingMessage)
	}
	r.Expiry = DefaultExpiry
	if v := form.Get("requested_expiry"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxExpiry {
			return r, invalid("requested_expiry must be 1 to %d seconds", MaxExpiry)
		}
		r.Expiry = n
	}
	if r.Expiry < MinEmailExpiry {
		// Auth0 sends push for 300 s or less; zeroauthy has no push (LR41c-6).
		return r, invalid("requested_expiry must be %d to %d seconds for the email channel; push notifications are not available", MinEmailExpiry, MaxExpiry)
	}
	r.Audience = form.Get("audience")
	return r, nil
}
