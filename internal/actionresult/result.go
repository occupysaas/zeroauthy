// Package actionresult defines dependency-neutral Action flow outcomes.
package actionresult

import "slices"

// TargetEdit is the target scope set after the flow's transaction edits.
type TargetEdit struct{ Scopes []string }

// RBACSnapshot preserves effective permissions, while token issuance still
// evaluates the current API definition and application policy.
type RBACSnapshot struct {
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}

// Effects are a flow's validated, accumulated results. Claims are filtered
// during minting. Metadata patches commit only when the flow completes.
type Effects struct {
	// RBAC is fixed before the first Action. Management API assignments made
	// by an Action affect the next issuance, including across redirects/code exchange.
	RBAC                      *RBACSnapshot
	AccessClaims, IDClaims    map[string]any
	AddScopes, RemoveScopes   []string
	Target                    *TargetEdit
	AppMetadata, UserMetadata map[string]any
	TxnMetadata               map[string]any
	// Ceiling is set by callers, not the engine: the authorized scopes
	// before the flow's target-scope edits, the refresh family's ceiling
	// (spec §7) when it differs from the issued scopes. Nil: the issued
	// scopes are the ceiling.
	Ceiling []string
}

// Denial is access.deny or validation.error. Code is "access_denied" for a
// post-login deny, the validation.error code, or the credentials-exchange
// deny code.
type Denial struct{ Code, Reason, UserMessage string }

// NotificationOutcome is the last retry/drop call of an email flow.
type NotificationOutcome struct{ Kind, Reason string }

// Redirect is a recorded api.redirect.sendUserTo (spec §8).
type Redirect struct {
	URL   string
	Query map[string]string
}

// Result is the outcome of a flow that did not fail.
type Result struct {
	Effects      Effects
	ResultURL    string
	Notification *NotificationOutcome
	Denied       *Denial
	Redirect     *Redirect
	ExecutionID  string
	Continuation map[string]string
}

// ApplyScopes returns the final access-token scope: filtered (the scopes
// left after target edits, API policy, RBAC and consent, spec §7) plus
// accessToken.addScope minus accessToken.removeScope, which bypass those
// checks as on Auth0. base is the scope set before Actions ran; it does not
// change the result and is kept for callers that log the difference. A nil
// receiver returns filtered unchanged.
func (e *Effects) ApplyScopes(base []string, filtered []string) []string {
	out := slices.Clone(filtered)
	if e == nil {
		return out
	}
	for _, s := range e.AddScopes {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return slices.DeleteFunc(out, func(s string) bool { return slices.Contains(e.RemoveScopes, s) })
}

// HasTokenEffects reports whether e changes a token: custom claims,
// accessToken scope edits, or a refresh ceiling that differs from the
// issued scopes. A nil e has none.
func (e *Effects) HasTokenEffects() bool {
	return e != nil && (len(e.AccessClaims) > 0 || len(e.IDClaims) > 0 || len(e.AddScopes) > 0 || len(e.RemoveScopes) > 0 ||
		e.Ceiling != nil || e.RBAC != nil)
}
