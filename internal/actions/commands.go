package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"maps"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
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
	trigger      string
	handler      string // the running handler (onContinuePostLogin admits recordMethod)
	canRedirect  bool
	customizeMFA bool

	eff          Effects
	target       []string // current target scopes
	resultURL    string
	notification *NotificationOutcome
	denied       *Denial
	redirect     *Redirect
	cache        []cacheOp // of the current Action
	cte          *cteAccum // custom-token-exchange only
}

func newAccum(trigger string, target []string, txnMeta map[string]any, canRedirect bool) *accum {
	a := &accum{trigger: trigger, canRedirect: canRedirect, target: slices.Clone(target)}
	if a.target == nil {
		a.target = []string{}
	}
	a.eff.TxnMetadata = maps.Clone(txnMeta)
	if trigger == TriggerCustomTokenExchange {
		a.cte = &cteAccum{}
	}
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

// apply validates one command against the trigger's api and accumulates it.
// Unknown ops, unsupported members and invalid arguments are errors.
func (a *accum) apply(c command) error {
	if c.Op == "invalid_api_call" {
		member, _ := optString(c, 0, "member")
		return invalid(member, "arguments must be JSON values")
	}
	if c.Op == "unsupported" {
		member, _ := optString(c, 0, "member")
		return fmt.Errorf("%w: api.%s", ErrUnsupported, member)
	}
	if !triggerSpecs[a.trigger].allows(c.Op) {
		return invalid(c.Op, "not available in the %s trigger", a.trigger)
	}
	if strings.HasPrefix(c.Op, "samlResponse.") {
		return a.applySAML(c)
	}
	switch c.Op {
	case "multifactor.enable", "authentication.challengeWith", "authentication.challengeWithAny", "authentication.enrollWith", "authentication.enrollWithAny":
		return a.applyMFA(c)
	case "session.revoke", "session.setExpiresAt", "session.setIdleExpiresAt", "session.setCookieMode",
		"session.setMetadata", "session.deleteMetadata", "session.evictMetadata",
		"refreshToken.setExpiresAt", "refreshToken.setIdleExpiresAt", "refreshToken.setMetadata",
		"refreshToken.deleteMetadata", "refreshToken.evictMetadata":
		return a.applySessionToken(c)
	case "user.setUserId":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		id, err := argString(c, 0, "user_id")
		if err != nil || id == "" || !utf8.ValidString(id) || utf8.RuneCountInString(id) > 255 || strings.IndexFunc(id, unicode.IsSpace) >= 0 {
			return invalid(c.Op, "invalid user_id")
		}
		a.eff.SignupUserID = id
	case "authentication.setPrimaryUser":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		id, err := argString(c, 0, "primary_user_id")
		if err != nil || id == "" || len(id) > 1024 || !utf8.ValidString(id) {
			return invalid(c.Op, "primary_user_id must be a non-empty user ID")
		}
		a.eff.PrimaryUserID = id
	case "authentication.recordMethod":
		if a.handler != "onContinuePostLogin" {
			return invalid(c.Op, "is available only in onContinuePostLogin")
		}
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		u, err := argString(c, 0, "provider_url")
		if err != nil || !recordMethodURL(u) {
			return invalid(c.Op, "provider_url must be an absolute https URL of at most %d bytes", maxRecordMethodURL)
		}
		if !slices.Contains(a.eff.RecordedMethods, u) {
			a.eff.RecordedMethods = append(a.eff.RecordedMethods, u)
		}
	case "refreshToken.revoke":
		if err := argCount(c, 0, 1); err != nil {
			return err
		}
		if _, err := optString(c, 0, "reason"); err != nil {
			return err
		}
		a.eff.RefreshTokenRevoke = true
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
		d := &Denial{Code: code, Reason: sanitizeReason(msg)}
		if a.trigger == TriggerPreUserRegistration {
			d.Reason = msg
			d.UserMessage = msg
		}
		a.setDenial(d)
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
	case "access.rejectInvalidSubjectToken", "authentication.setUserById", "authentication.setUserByConnection",
		"authentication.setOrganization", "authentication.setActor":
		return a.applyTokenExchange(c)
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
	case "transaction.setResultUrl":
		return a.setResultURL(c)
	case "notification.retry", "notification.drop":
		if err := argCount(c, 0, 1); err != nil {
			return err
		}
		reason, err := optString(c, 0, "reason")
		if err != nil {
			return err
		}
		a.notification = &NotificationOutcome{Kind: strings.TrimPrefix(c.Op, "notification."), Reason: truncateChars(reason, actionsrules.Inventory().Limits["notification_reason_chars"])}
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
	if a.trigger == TriggerCustomTokenExchange {
		if err := argCount(c, 1, 2); err != nil {
			return err
		}
		code, err := argString(c, 0, "code")
		if err != nil {
			return err
		}
		if err := checkCode(c.Op, code); err != nil {
			return err
		}
		reason, err := optString(c, 1, "reason")
		if err != nil {
			return err
		}
		a.setDenial(&Denial{Code: code, Reason: sanitizeReason(reason)})
		return nil
	}
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
	if a.trigger == TriggerPreUserRegistration {
		if err := argCount(c, 0, 2); err != nil {
			return err
		}
		reason, err := optString(c, 0, "reason")
		if err != nil {
			return err
		}
		message, err := optString(c, 1, "user message")
		if err != nil {
			return err
		}
		a.setDenial(&Denial{Code: "extensibility_error", Reason: reason, UserMessage: message})
		return nil
	}
	if err := argCount(c, 0, 1); err != nil {
		return err
	}
	reason, err := optString(c, 0, "reason")
	if err != nil {
		return err
	}
	if a.trigger != TriggerResetPostChallenge {
		reason = sanitizeReason(reason)
	}
	a.setDenial(&Denial{Code: "access_denied", Reason: reason})
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
	if !a.canRedirect {
		return ErrRedirectNotAllowed
	}
	a.redirect = r
	return nil
}

// truncateChars uses characters, rather than bytes, to retain localized reasons.
func truncateChars(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}

func (a *accum) setResultURL(c command) error {
	if err := argCount(c, 1, 2); err != nil {
		return err
	}
	raw, err := argString(c, 0, "url")
	if err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) {
		return invalid(c.Op, "url must be absolute https, or http on localhost")
	}
	query, err := redirectQuery(c)
	if err != nil {
		return err
	}
	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	a.resultURL = u.String()
	return nil
}

func redirectQuery(c command) (map[string]string, error) {
	query := map[string]string{}
	if len(c.Args) < 2 || string(c.Args[1]) == "null" {
		return query, nil
	}
	var opts map[string]json.RawMessage
	if json.Unmarshal(c.Args[1], &opts) != nil || opts == nil {
		return nil, invalid(c.Op, "options must be an object")
	}
	if raw, ok := opts["query"]; ok {
		var values map[string]any
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return nil, invalid(c.Op, "query must be an object")
		}
		for k, v := range values {
			switch t := v.(type) {
			case string:
				query[k] = t
			case float64, bool:
				b, _ := json.Marshal(t)
				query[k] = string(b)
			default:
				return nil, invalid(c.Op, "query values must be strings, numbers or booleans")
			}
		}
	}
	return query, nil
}

// Limits and documented values of the custom-token-exchange api.
const (
	maxActorDepth      = 5
	maxActorProperties = 5
	maxRefBytes        = 1024
)

// connectionAttributes are the documented setUserByConnection attributes;
// user_id is required. The bool ones take a boolean, the rest a string.
var connectionAttributes = map[string]bool{
	"user_id": false, "email": false, "email_verified": true, "verify_email": true, "phone_number": false, "phone_verified": true,
	"username": false, "name": false, "given_name": false, "family_name": false, "nickname": false, "picture": false,
}

func (a *accum) applyTokenExchange(c command) error {
	if a.cte == nil {
		return invalid(c.Op, "not available in the %s trigger", a.trigger)
	}
	switch c.Op {
	case "access.rejectInvalidSubjectToken":
		if err := argCount(c, 0, 1); err != nil {
			return err
		}
		if _, err := optString(c, 0, "reason"); err != nil {
			return err
		}
		a.cte.rejected = true
	case "authentication.setUserById":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		id, err := argRef(c, 0, "user id")
		if err != nil {
			return err
		}
		a.cte.selectUser(id, "", nil, "", "")
	case "authentication.setUserByConnection":
		return a.setUserByConnection(c)
	case "authentication.setOrganization":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		ref, err := argRef(c, 0, "organization id or name")
		if err != nil {
			return err
		}
		a.cte.result.OrganizationRef = ref
	case "authentication.setActor":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		var actor map[string]any
		if json.Unmarshal(c.Args[0], &actor) != nil || actor == nil {
			return invalid(c.Op, "actor must be an object")
		}
		if err := checkActor(c.Op, actor, 1); err != nil {
			return err
		}
		a.cte.result.Actor = actor
	}
	return nil
}

// argRef is a non-empty identifier or name argument.
func argRef(c command, i int, what string) (string, error) {
	s, err := argString(c, i, what)
	if err != nil {
		return "", err
	}
	if s == "" || len(s) > maxRefBytes || !utf8.ValidString(s) {
		return "", invalid(c.Op, "%s must be 1-%d bytes", what, maxRefBytes)
	}
	return s, nil
}

// checkActor bounds the actor claim: at most maxActorDepth actors (the root
// plus nested "act" levels, RFC 8693 section 4.1), a non-empty string "sub"
// at every level, and at most maxActorProperties custom properties per level
// (sub and act do not count), whose values are strings, numbers or booleans.
func checkActor(op string, actor map[string]any, depth int) error {
	if depth > maxActorDepth {
		return invalid(op, "actor nests at most %d levels", maxActorDepth)
	}
	if sub, _ := actor["sub"].(string); sub == "" || len(sub) > maxRefBytes {
		return invalid(op, "every actor level needs a non-empty string sub of at most %d bytes", maxRefBytes)
	}
	custom := 0
	for k, v := range actor {
		if len(k) > maxRefBytes {
			return invalid(op, "actor property names are at most %d bytes", maxRefBytes)
		}
		switch t := v.(type) {
		case string:
			if len(t) > maxRefBytes {
				return invalid(op, "actor string values are at most %d bytes", maxRefBytes)
			}
		case float64, bool:
		case map[string]any:
			if k != "act" {
				return invalid(op, "only \"act\" may hold an object")
			}
			if err := checkActor(op, t, depth+1); err != nil {
				return err
			}
			continue
		default:
			return invalid(op, "actor values must be strings, numbers or booleans")
		}
		if k == "act" {
			return invalid(op, "act must be an actor object")
		}
		if k != "sub" {
			custom++
		}
	}
	if custom > maxActorProperties {
		return invalid(op, "each actor level has at most %d custom properties", maxActorProperties)
	}
	return nil
}

func (a *accum) setUserByConnection(c command) error {
	if err := argCount(c, 2, 3); err != nil {
		return err
	}
	name, err := argRef(c, 0, "connection name")
	if err != nil {
		return err
	}
	var attrs map[string]any
	if json.Unmarshal(c.Args[1], &attrs) != nil || attrs == nil {
		return invalid(c.Op, "attributes must be an object")
	}
	for k, v := range attrs {
		isBool, ok := connectionAttributes[k]
		if !ok {
			return invalid(c.Op, "unknown attribute %q", k)
		}
		if _, gotBool := v.(bool); isBool != gotBool {
			return invalid(c.Op, "attribute %q has the wrong type", k)
		}
		if s, isString := v.(string); !isBool && !isString || isString && (len(s) > maxRefBytes || !utf8.ValidString(s)) {
			return invalid(c.Op, "attribute %q must be a string of at most %d bytes", k, maxRefBytes)
		}
	}
	if id, _ := attrs["user_id"].(string); id == "" {
		return invalid(c.Op, "attributes.user_id is required")
	}
	creation, update := CreateIfNotExists, UpdateNever // C14
	if len(c.Args) == 3 && string(c.Args[2]) != "null" {
		var opts map[string]any
		if json.Unmarshal(c.Args[2], &opts) != nil || opts == nil {
			return invalid(c.Op, "options must be an object")
		}
		for k, v := range opts {
			s, _ := v.(string)
			switch {
			case k == "creationBehavior" && (s == CreateIfNotExists || s == CreateNever):
				creation = s
			case k == "updateBehavior" && (s == UpdateNever || s == UpdateReplace):
				update = s
			default:
				return invalid(c.Op, "option %q is unknown or has an unsupported value", k)
			}
		}
	}
	a.cte.selectUser("", name, attrs, creation, update)
	return nil
}

// SAML response limits (Plan 37a, aligned with the samlp add-on).
const (
	maxSAMLValue      = 16384
	maxSAMLAttributes = 100
	maxSAMLValues     = 100
	maxSAMLLifetime   = 86400
)

func samlBoolArg(c command) (*bool, error) {
	if err := argCount(c, 1, 1); err != nil {
		return nil, err
	}
	var b bool
	if json.Unmarshal(c.Args[0], &b) != nil {
		return nil, invalid(c.Op, "argument must be a boolean")
	}
	return &b, nil
}

func samlStringArg(c command, allowed ...string) (string, error) {
	if err := argCount(c, 1, 1); err != nil {
		return "", err
	}
	v, err := argString(c, 0, "value")
	if err != nil {
		return "", err
	}
	if len(v) > maxSAMLValue {
		return "", invalid(c.Op, "value is too long")
	}
	if len(allowed) > 0 && !slices.Contains(allowed, v) {
		return "", invalid(c.Op, "value must be one of %s", strings.Join(allowed, ", "))
	}
	return v, nil
}

// applySAML validates one api.samlResponse setter.
func (a *accum) applySAML(c command) error {
	if a.eff.SAML == nil {
		a.eff.SAML = &actionresult.SAMLEffects{}
	}
	s := a.eff.SAML
	var err error
	str := func(dst *string, allowed ...string) {
		var v string
		if v, err = samlStringArg(c, allowed...); err == nil {
			*dst = v
		}
	}
	boolean := func(dst **bool) { *dst, err = samlBoolArg(c) }
	switch strings.TrimPrefix(c.Op, "samlResponse.") {
	case "setAttribute":
		if err = argCount(c, 2, 2); err != nil {
			return err
		}
		var name string
		if name, err = argString(c, 0, "attribute"); err != nil {
			return err
		}
		if name == "" || len(name) > 1024 {
			return invalid(c.Op, "attribute name must be 1 to 1024 characters")
		}
		var raw any
		if json.Unmarshal(c.Args[1], &raw) != nil {
			return invalid(c.Op, "invalid value")
		}
		var vals []string
		switch v := raw.(type) {
		case nil:
			delete(s.Attributes, name)
			if !slices.Contains(s.RemovedAttributes, name) {
				s.RemovedAttributes = append(s.RemovedAttributes, name)
			}
			return nil
		case string:
			vals = []string{v}
		case bool, float64:
			vals = []string{fmt.Sprint(v)}
		case []any:
			for _, e := range v {
				switch ev := e.(type) {
				case string:
					vals = append(vals, ev)
				case bool, float64:
					vals = append(vals, fmt.Sprint(ev))
				default:
					return invalid(c.Op, "array values must be strings, numbers or booleans")
				}
			}
		default:
			return invalid(c.Op, "value must be a string, number, boolean or array of them")
		}
		if len(vals) > maxSAMLValues {
			return invalid(c.Op, "too many values")
		}
		for _, v := range vals {
			if len(v) > maxSAMLValue {
				return invalid(c.Op, "value is too long")
			}
		}
		if s.Attributes == nil {
			s.Attributes = map[string][]string{}
		}
		if _, exists := s.Attributes[name]; !exists && len(s.Attributes) >= maxSAMLAttributes {
			return invalid(c.Op, "too many attributes")
		}
		s.Attributes[name] = vals
		s.RemovedAttributes = slices.DeleteFunc(s.RemovedAttributes, func(n string) bool { return n == name })
		return nil
	case "setAudience":
		str(&s.Audience)
	case "setRecipient":
		str(&s.Recipient)
	case "setDestination":
		str(&s.Destination)
	case "setIssuer":
		str(&s.Issuer)
	case "setRelayState":
		var v string
		if v, err = samlStringArg(c); err == nil {
			s.RelayState = &v
		}
	case "setCreateUpnClaim":
		boolean(&s.CreateUpnClaim)
	case "setPassthroughClaimsWithNoMapping":
		boolean(&s.PassthroughClaimsWithNoMapping)
	case "setMapUnknownClaimsAsIs":
		boolean(&s.MapUnknownClaimsAsIs)
	case "setMapIdentities":
		boolean(&s.MapIdentities)
	case "setSignResponse":
		boolean(&s.SignResponse)
	case "setIncludeAttributeNameFormat":
		boolean(&s.IncludeAttributeNameFormat)
	case "setTypedAttributes":
		boolean(&s.TypedAttributes)
	case "setSignatureAlgorithm":
		str(&s.SignatureAlgorithm, "rsa-sha256", "rsa-sha1")
	case "setDigestAlgorithm":
		str(&s.DigestAlgorithm, "sha256", "sha1")
	case "setEncryptionAlgorithm":
		str(&s.EncryptionAlgorithm, "aes256-gcm", "aes256-cbc")
	case "setLifetimeInSeconds":
		if err = argCount(c, 1, 1); err != nil {
			return err
		}
		var n float64
		if json.Unmarshal(c.Args[0], &n) != nil || n != float64(int(n)) || n < 1 || n > maxSAMLLifetime {
			return invalid(c.Op, "lifetime must be an integer from 1 to %d", maxSAMLLifetime)
		}
		v := int(n)
		s.LifetimeInSeconds = &v
	case "setNameIdentifierFormat":
		str(&s.NameIdentifierFormat)
	case "setAuthnContextClassRef":
		str(&s.AuthnContextClassRef)
	case "setNameIdentifierProbes":
		if err = argCount(c, 1, 1); err != nil {
			return err
		}
		var probes []string
		if json.Unmarshal(c.Args[0], &probes) != nil || len(probes) > 16 {
			return invalid(c.Op, "probes must be an array of up to 16 strings")
		}
		s.NameIdentifierProbes = probes
	case "setSigningCert":
		str(&s.SigningCert)
	case "setEncryptionCert":
		str(&s.EncryptionCert)
	case "setEncryptionPublicKey":
		str(&s.EncryptionPublicKey)
	case "setCert":
		str(&s.Cert)
	case "setKey":
		str(&s.Key)
	default:
		return invalid(c.Op, "unknown samlResponse setter")
	}
	return err
}

// Plan 40 limits (Plan 48 metadata limits; recordMethod URL).
const (
	maxActionMetadataKeys  = 25
	maxActionMetadataRunes = 255
	maxRecordMethodURL     = 2048
)

func recordMethodURL(raw string) bool {
	if raw == "" || len(raw) > maxRecordMethodURL {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// argMillis reads a positive JSON integer of milliseconds since the epoch.
func argMillis(c command, i int) (time.Time, error) {
	var n float64
	if i >= len(c.Args) || json.Unmarshal(c.Args[i], &n) != nil || n <= 0 || n != math.Trunc(n) || n > 1e15 {
		return time.Time{}, invalid(c.Op, "expects a positive time in milliseconds since the epoch")
	}
	return time.UnixMilli(int64(n)).UTC(), nil
}

// applySessionToken accumulates api.session and api.refreshToken setters
// and metadata calls (Plan 40). Expiry values are capped when applied.
func (a *accum) applySessionToken(c command) error {
	ns, name, _ := strings.Cut(c.Op, ".")
	var expires, idle **time.Time
	var md *[]MetadataOp
	if ns == "session" {
		if a.eff.Session == nil {
			a.eff.Session = &SessionEffects{}
		}
		expires, idle, md = &a.eff.Session.ExpiresAt, &a.eff.Session.IdleExpiresAt, &a.eff.Session.Metadata
	} else {
		if a.eff.RefreshToken == nil {
			a.eff.RefreshToken = &RefreshTokenEffects{}
		}
		expires, idle, md = &a.eff.RefreshToken.ExpiresAt, &a.eff.RefreshToken.IdleExpiresAt, &a.eff.RefreshToken.Metadata
	}
	switch name {
	case "revoke":
		if err := argCount(c, 0, 2); err != nil {
			return err
		}
		reason, err := optString(c, 0, "reason")
		if err != nil {
			return err
		}
		rev := &Revocation{Reason: truncateRunes(reason, 1024)}
		if len(c.Args) > 1 && string(c.Args[1]) != "null" {
			var opts struct {
				PreserveRefreshTokens *bool `json:"preserveRefreshTokens"`
			}
			if json.Unmarshal(c.Args[1], &opts) != nil {
				return invalid(c.Op, "options must be an object")
			}
			rev.PreserveRefreshTokens = opts.PreserveRefreshTokens != nil && *opts.PreserveRefreshTokens
		}
		a.eff.Session.Revoke = rev
	case "setExpiresAt", "setIdleExpiresAt":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		at, err := argMillis(c, 0)
		if err != nil {
			return err
		}
		if name == "setExpiresAt" {
			*expires = &at
		} else {
			*idle = &at
		}
	case "setCookieMode":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		mode, err := argString(c, 0, "mode")
		if err != nil || (mode != "persistent" && mode != "non-persistent") {
			return invalid(c.Op, "mode must be persistent or non-persistent")
		}
		a.eff.Session.CookieMode = mode
	case "setMetadata":
		if err := argCount(c, 2, 2); err != nil {
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
		if k == "" || utf8.RuneCountInString(k) > maxActionMetadataRunes || utf8.RuneCountInString(v) > maxActionMetadataRunes {
			return invalid(c.Op, "key and value must be 1 to %d characters", maxActionMetadataRunes)
		}
		*md = append(*md, MetadataOp{Op: "set", Key: k, Value: v})
	case "deleteMetadata":
		if err := argCount(c, 1, 1); err != nil {
			return err
		}
		k, err := argString(c, 0, "key")
		if err != nil {
			return err
		}
		*md = append(*md, MetadataOp{Op: "delete", Key: k})
	case "evictMetadata":
		if err := argCount(c, 0, 0); err != nil {
			return err
		}
		*md = append(*md, MetadataOp{Op: "evict"})
	default:
		return invalid(c.Op, "unknown member")
	}
	return nil
}

// ApplyMetadataOps applies ops in call order to current, returning the new
// map, or an error when it exceeds the key limit.
func ApplyMetadataOps(current map[string]string, ops []MetadataOp) (map[string]string, error) {
	out := maps.Clone(current)
	if out == nil {
		out = map[string]string{}
	}
	for _, op := range ops {
		switch op.Op {
		case "set":
			out[op.Key] = op.Value
		case "delete":
			delete(out, op.Key)
		case "evict":
			clear(out)
		}
	}
	if len(out) > maxActionMetadataKeys {
		return nil, fmt.Errorf("%w: metadata may hold at most %d keys", ErrInvalidCommand, maxActionMetadataKeys)
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
