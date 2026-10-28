package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// Trigger IDs.
const (
	TriggerPostLogin           = "post-login"
	TriggerCredentialsExchange = "credentials-exchange"
)

var (
	// ErrInvalidCommand reports an api call the server refuses: an unknown
	// member or an invalid argument. The flow fails closed.
	ErrInvalidCommand = errors.New("actions: invalid api call")
	// ErrUnsupported reports a call to an api member zeroauthy does not
	// support; the flow fails closed even when the Action caught the error.
	ErrUnsupported = errors.New("actions: api member not supported by zeroauthy")
	// ErrRedirectNotAllowed reports api.redirect.sendUserTo where
	// canRedirect() is false.
	ErrRedirectNotAllowed = errors.New("actions: redirect not allowed in this flow")
	// ErrRedirectNotSupported reports api.redirect.sendUserTo until
	// redirect/continue exists (Task 9): the flow fails closed rather than
	// skip the remaining Actions.
	ErrRedirectNotSupported = errors.New("actions: api.redirect.sendUserTo is not supported yet")
)

// Local bounds on deny and validation.error values, which reach OAuth
// error/error_description (RFC 6749 §5.2 charset: %x20-21 / %x23-5B /
// %x5D-7E). An error code outside them fails the flow closed; a reason or
// message is sanitized instead (D-0053-style local choice), so a localized
// deny still denies rather than becoming a server error.
const (
	maxErrorCodeBytes   = 128
	maxErrorReasonBytes = 512
)

// oauthErrorChar reports whether c is in the RFC 6749 error charset.
func oauthErrorChar(c rune) bool {
	return c >= 0x20 && c <= 0x7e && c != '"' && c != '\\'
}

func checkCode(op, code string) error {
	if code == "" || len(code) > maxErrorCodeBytes || strings.IndexFunc(code, func(r rune) bool { return !oauthErrorChar(r) }) >= 0 {
		return invalid(op, "error code must be 1-%d printable ASCII characters without '\"' or '\\'", maxErrorCodeBytes)
	}
	return nil
}

// sanitizeReason replaces every character outside the RFC 6749 error
// charset (including each non-ASCII character and invalid byte) with '?'
// and cuts the result at maxErrorReasonBytes.
func sanitizeReason(reason string) string {
	var b strings.Builder
	for _, r := range reason {
		if b.Len() >= maxErrorReasonBytes {
			break
		}
		if !oauthErrorChar(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// credentialsDenyCodes are the documented credentials-exchange deny codes.
var credentialsDenyCodes = []string{"invalid_scope", "invalid_request", "server_error"}

// command is one api call recorded by the runner.
type command struct {
	Op   string            `json:"op"`
	Args []json.RawMessage `json:"args"`
}

// cacheOp is one validated cache write.
type cacheOp struct {
	delete         bool
	key, value     string
	ttl, expiresAt int64 // ms; 0 = unset
}

// accum accumulates a flow's effects from validated commands. Nothing the
// runner sends is used before it passes apply.
type accum struct {
	trigger     string
	canRedirect bool

	eff      Effects
	target   []string // current target scopes
	denied   *Denial
	redirect *Redirect
	cache    []cacheOp // of the current Action
}

func newAccum(trigger string, target []string, txnMeta map[string]any, canRedirect bool) *accum {
	a := &accum{trigger: trigger, canRedirect: canRedirect, target: slices.Clone(target)}
	if a.target == nil {
		a.target = []string{}
	}
	a.eff.TxnMetadata = maps.Clone(txnMeta)
	return a
}

func invalid(op, format string, args ...any) error {
	return fmt.Errorf("%w: api.%s: %s", ErrInvalidCommand, op, fmt.Sprintf(format, args...))
}

// argCount checks the number of arguments.
func argCount(c command, lo, hi int) error {
	if len(c.Args) < lo || len(c.Args) > hi {
		if lo == hi {
			return invalid(c.Op, "expects %d argument(s)", lo)
		}
		return invalid(c.Op, "expects %d to %d arguments", lo, hi)
	}
	return nil
}

func argString(c command, i int, what string) (string, error) {
	var s string
	if i >= len(c.Args) || json.Unmarshal(c.Args[i], &s) != nil {
		return "", invalid(c.Op, "%s must be a string", what)
	}
	return s, nil
}

// optString is an absent or null argument, or a string.
func optString(c command, i int, what string) (string, error) {
	if i >= len(c.Args) || string(c.Args[i]) == "null" {
		return "", nil
	}
	return argString(c, i, what)
}

func argValue(c command, i int) (any, error) {
	var v any
	if i >= len(c.Args) || json.Unmarshal(c.Args[i], &v) != nil {
		return nil, invalid(c.Op, "argument %d must be a JSON value", i+1)
	}
	return v, nil
}

func validScope(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t\r\n\"\\") && utf8.ValidString(s)
}

func argScope(c command, i int) (string, error) {
	s, err := argString(c, i, "scope")
	if err != nil {
		return "", err
	}
	if !validScope(s) {
		return "", invalid(c.Op, "invalid scope %q", s)
	}
	return s, nil
}

// postLoginOnly lists ops the credentials-exchange api does not have.
var postLoginOnly = map[string]bool{
	"accessToken.addScope": true, "accessToken.removeScope": true, "idToken.setCustomClaim": true,
	"transaction.setMetadata": true, "user.setAppMetadata": true, "user.setUserMetadata": true,
	"validation.error": true, "redirect.sendUserTo": true,
}

// apply validates one command against the trigger's api and accumulates it.
// Unknown ops, unsupported members and invalid arguments are errors.
func (a *accum) apply(c command) error {
	if c.Op == "unsupported" {
		member, _ := optString(c, 0, "member")
		return fmt.Errorf("%w: api.%s", ErrUnsupported, member)
	}
	if a.trigger == TriggerCredentialsExchange && postLoginOnly[c.Op] {
		return invalid(c.Op, "not available in the credentials-exchange trigger")
	}
	switch c.Op {
	case "access.deny":
		return a.deny(c)
	case "validation.error":
		if err := argCount(c, 2, 2); err != nil {
			return err
		}
		code, err := argString(c, 0, "error code")
		if err != nil {
			return err
		}
		msg, err := argString(c, 1, "error message")
		if err != nil {
			return err
		}
		if err := checkCode(c.Op, code); err != nil {
			return err
		}
		a.setDenial(&Denial{Code: code, Reason: sanitizeReason(msg)})
	case "accessToken.setCustomClaim", "idToken.setCustomClaim":
		if err := argCount(c, 2, 2); err != nil {
			return err
		}
		name, err := argString(c, 0, "claim name")
		if err != nil {
			return err
		}
		if name == "" {
			return invalid(c.Op, "claim name is required")
		}
		v, err := argValue(c, 1)
		if err != nil {
			return err
		}
		dst := &a.eff.AccessClaims
		if c.Op == "idToken.setCustomClaim" {
			dst = &a.eff.IDClaims
		}
		if *dst == nil {
			*dst = map[string]any{}
		}
		(*dst)[name] = v
	case "accessToken.addScope", "accessToken.removeScope":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		s, err := argScope(c, 0)
		if err != nil {
			return err
		}
		add, remove := &a.eff.AddScopes, &a.eff.RemoveScopes
		if c.Op == "accessToken.removeScope" {
			add, remove = remove, add
		}
		*remove = slices.DeleteFunc(*remove, func(x string) bool { return x == s })
		if !slices.Contains(*add, s) {
			*add = append(*add, s)
		}
	case "transaction.addTargetScope", "transaction.removeTargetScope":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		s, err := argScope(c, 0)
		if err != nil {
			return err
		}
		a.target = slices.DeleteFunc(a.target, func(x string) bool { return x == s })
		if c.Op == "transaction.addTargetScope" {
			a.target = append(a.target, s)
		}
		a.editTarget()
	case "transaction.setTargetScopes":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		var list []string
		if json.Unmarshal(c.Args[0], &list) != nil {
			return invalid(c.Op, "scopes must be an array of strings")
		}
		next := []string{}
		for _, s := range list {
			if !validScope(s) {
				return invalid(c.Op, "invalid scope %q", s)
			}
			if !slices.Contains(next, s) {
				next = append(next, s)
			}
		}
		a.target = next
		a.editTarget()
	case "transaction.clearTargetScopes":
		if err := argCount(c, 0, 0); err != nil {
			return err
		}
		a.target = []string{}
		a.editTarget()
	case "transaction.setMetadata":
		return a.setTxnMetadata(c)
	case "user.setAppMetadata", "user.setUserMetadata":
		return a.setUserMetadata(c)
	case "cache.set":
		return a.cacheSet(c)
	case "cache.delete":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		k, err := argString(c, 0, "key")
		if err != nil {
			return err
		}
		a.cache = append(a.cache, cacheOp{delete: true, key: k})
	case "redirect.sendUserTo":
		return a.sendUserTo(c)
	default:
		return invalid(c.Op, "unknown api member")
	}
	return nil
}

// setDenial keeps the first denial of the flow.
func (a *accum) setDenial(d *Denial) {
	if a.denied == nil {
		a.denied = d
	}
}

func (a *accum) deny(c command) error {
	if a.trigger == TriggerCredentialsExchange {
		if err := argCount(c, 1, 2); err != nil {
			return err
		}
		code, err := argString(c, 0, "code")
		if err != nil {
			return err
		}
		if !slices.Contains(credentialsDenyCodes, code) {
			return invalid(c.Op, "code must be one of %s", strings.Join(credentialsDenyCodes, ", "))
		}
		reason, err := optString(c, 1, "reason")
		if err != nil {
			return err
		}
		a.setDenial(&Denial{Code: code, Reason: sanitizeReason(reason)})
		return nil
	}
	if err := argCount(c, 0, 1); err != nil {
		return err
	}
	reason, err := optString(c, 0, "reason")
	if err != nil {
		return err
	}
	a.setDenial(&Denial{Code: "access_denied", Reason: sanitizeReason(reason)})
	return nil
}

func (a *accum) editTarget() {
	a.eff.Target = &TargetEdit{Scopes: slices.Clone(a.target)}
}

func (a *accum) setTxnMetadata(c command) error {
	if err := argCount(c, 2, 2); err != nil {
		return err
	}
	k, err := argString(c, 0, "key")
	if err != nil {
		return err
	}
	lim := actionsrules.Inventory().Limits
	if k == "" || utf8.RuneCountInString(k) > lim["transaction_metadata_key_max"] {
		return invalid(c.Op, "key must be 1-%d characters", lim["transaction_metadata_key_max"])
	}
	v, err := argValue(c, 1)
	if err != nil {
		return err
	}
	next := maps.Clone(a.eff.TxnMetadata)
	if next == nil {
		next = map[string]any{}
	}
	switch t := v.(type) {
	case nil:
		delete(next, k)
	case string, float64, bool:
		size := len(c.Args[1])
		if s, ok := t.(string); ok {
			size = len(s)
		}
		if size > lim["transaction_metadata_value_bytes_max"] {
			return invalid(c.Op, "value exceeds %d bytes", lim["transaction_metadata_value_bytes_max"])
		}
		next[k] = t
	default:
		return invalid(c.Op, "value must be a string, number or boolean")
	}
	if b, _ := json.Marshal(next); len(b) > lim["transaction_metadata_total_bytes_max"] {
		return invalid(c.Op, "transaction metadata exceeds %d bytes", lim["transaction_metadata_total_bytes_max"])
	}
	a.eff.TxnMetadata = next
	return nil
}

func (a *accum) setUserMetadata(c command) error {
	if err := argCount(c, 2, 2); err != nil {
		return err
	}
	k, err := argString(c, 0, "name")
	if err != nil {
		return err
	}
	v, err := argValue(c, 1)
	if err != nil {
		return err
	}
	field, dst := "app_metadata", &a.eff.AppMetadata
	if c.Op == "user.setUserMetadata" {
		field, dst = "user_metadata", &a.eff.UserMetadata
	}
	// The same rules as PATCH /api/v2/users/{id} (null deletes the key).
	if err := userrules.CheckMetadata(field, map[string]any{k: v}); err != nil || k == "" {
		if err == nil {
			err = errors.New("name is required")
		}
		return invalid(c.Op, "%v", err)
	}
	if *dst == nil {
		*dst = map[string]any{}
	}
	(*dst)[k] = v
	if err := userrules.CheckMetadata(field, *dst); err != nil {
		return invalid(c.Op, "%v", err)
	}
	return nil
}

func (a *accum) cacheSet(c command) error {
	if err := argCount(c, 2, 3); err != nil {
		return err
	}
	k, err := argString(c, 0, "key")
	if err != nil {
		return err
	}
	v, err := argString(c, 1, "value")
	if err != nil {
		return err
	}
	lim := actionsrules.Inventory().Limits
	if k == "" || len(k) > lim["cache_key_bytes_max"] {
		return invalid(c.Op, "key must be 1-%d bytes", lim["cache_key_bytes_max"])
	}
	if len(v) > lim["cache_value_bytes_max"] {
		return invalid(c.Op, "value exceeds %d bytes", lim["cache_value_bytes_max"])
	}
	op := cacheOp{key: k, value: v}
	if len(c.Args) == 3 && string(c.Args[2]) != "null" {
		var opts map[string]json.RawMessage
		if json.Unmarshal(c.Args[2], &opts) != nil {
			return invalid(c.Op, "options must be an object")
		}
		for name, raw := range opts {
			var n float64
			if json.Unmarshal(raw, &n) != nil || n <= 0 || n > 1e15 {
				return invalid(c.Op, "%s must be a positive number", name)
			}
			switch name {
			case "ttl":
				op.ttl = int64(n)
			case "expires_at":
				op.expiresAt = int64(n)
			default:
				return invalid(c.Op, "unknown option %q", name)
			}
		}
	}
	a.cache = append(a.cache, op)
	return nil
}

func (a *accum) sendUserTo(c command) error {
	if err := argCount(c, 1, 2); err != nil {
		return err
	}
	raw, err := argString(c, 0, "url")
	if err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return invalid(c.Op, "url must be an absolute http(s) URL")
	}
	r := &Redirect{URL: raw, Query: map[string]string{}}
	if len(c.Args) == 2 && string(c.Args[1]) != "null" {
		var opts struct {
			Query map[string]any `json:"query"`
		}
		if json.Unmarshal(c.Args[1], &opts) != nil {
			return invalid(c.Op, "options must be an object")
		}
		for k, v := range opts.Query {
			switch t := v.(type) {
			case string:
				r.Query[k] = t
			case float64, bool:
				b, _ := json.Marshal(t)
				r.Query[k] = string(b)
			default:
				return invalid(c.Op, "query values must be strings, numbers or booleans")
			}
		}
	}
	// Until Task 9 adds continue state (and the canRedirect check with
	// ErrRedirectNotAllowed), a redirect would skip the remaining Actions:
	// the validated redirect r is not kept and the flow fails closed,
	// whether or not it could redirect.
	_ = r
	return ErrRedirectNotSupported
}
