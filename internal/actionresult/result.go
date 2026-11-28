// Package actionresult defines dependency-neutral Action flow outcomes.
package actionresult

import (
	"slices"
	"time"
)

// TargetEdit is the target scope set after the flow's transaction edits.
type TargetEdit struct{ Scopes []string }

// RBACSnapshot preserves effective permissions, while token issuance still
// evaluates the current API definition and application policy.
type RBACSnapshot struct {
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}

// MFAEffects carries validated Action MFA instructions. Each Factors entry is
// one call's ordered set of primary and alternative factors.
type MFAEffects struct {
	PhonePreferredMethod string
	Provider             string
	AllowRememberBrowser bool
	Any                  bool // the Action requested an initial factor selector
	Mode                 string
	Factors              [][]string
}

// Effects are a flow's validated, accumulated results. Claims are filtered
// during minting. Metadata patches commit only when the flow completes.
type Effects struct {
	MFA                *MFAEffects
	RefreshTokenRevoke bool
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
	// SAML holds api.samlResponse.* settings for this SAML response (Plan 37a).
	SAML *SAMLEffects
	// Session holds api.session.* calls (Plan 40); nil when none was made.
	Session *SessionEffects `json:",omitempty"`
	// RefreshToken holds api.refreshToken setters and metadata calls.
	RefreshToken *RefreshTokenEffects `json:",omitempty"`
	// PrimaryUserID is the last api.authentication.setPrimaryUser argument.
	PrimaryUserID string `json:",omitempty"`
	// RecordedMethods are api.authentication.recordMethod provider URLs.
	RecordedMethods []string `json:",omitempty"`
}

// MetadataOp is one metadata call, applied in call order: "set" (Key,
// Value), "delete" (Key) or "evict" (every key).
type MetadataOp struct{ Op, Key, Value string }

// Revocation is an api.session.revoke call.
type Revocation struct {
	Reason                string
	PreserveRefreshTokens bool
}

// SessionEffects are a flow's api.session calls. The expiry setters can
// only shorten the session (LR40-3); callers cap them when applying.
type SessionEffects struct {
	Revoke                   *Revocation
	ExpiresAt, IdleExpiresAt *time.Time
	CookieMode               string // "", "persistent" or "non-persistent"
	Metadata                 []MetadataOp
}

// RefreshTokenEffects are a flow's api.refreshToken setters and metadata
// calls (revoke stays Effects.RefreshTokenRevoke).
type RefreshTokenEffects struct {
	ExpiresAt, IdleExpiresAt *time.Time
	Metadata                 []MetadataOp
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

// SAMLEffects are the api.samlResponse.* settings of one SAML response
// (Plan 37a). Empty strings and nil pointers leave the add-on value. Key is
// a PEM private key from the Action: sensitive, never logged.
type SAMLEffects struct {
	Attributes                                                               map[string][]string `json:"attributes,omitempty"`
	RemovedAttributes                                                        []string            `json:"removed_attributes,omitempty"`
	Audience, Recipient, Destination, Issuer                                 string              `json:",omitempty"`
	RelayState                                                               *string             `json:",omitempty"`
	CreateUpnClaim, PassthroughClaimsWithNoMapping, MapUnknownClaimsAsIs     *bool               `json:",omitempty"`
	MapIdentities, SignResponse, IncludeAttributeNameFormat, TypedAttributes *bool               `json:",omitempty"`
	SignatureAlgorithm, DigestAlgorithm, EncryptionAlgorithm                 string              `json:",omitempty"`
	LifetimeInSeconds                                                        *int                `json:",omitempty"`
	NameIdentifierFormat, AuthnContextClassRef, SigningCert                  string              `json:",omitempty"`
	NameIdentifierProbes                                                     []string            `json:",omitempty"`
	EncryptionCert, EncryptionPublicKey, Cert                                string              `json:",omitempty"`
	// Key is the Action-supplied PEM private key; its JSON name is scrubbed
	// from logs (logscrub "privatekey").
	Key string `json:"private_key,omitempty"`
}
