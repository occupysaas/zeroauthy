package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/keys"
)

// effectsLabel names the sealed form of a flow's token effects.
const effectsLabel = "action-effects/v1"

// What sealed effects are bound to, besides the tenant: a blob copied to
// another code, device code or consent transaction does not open.
const (
	SealCode    = "code"    // an authorization code (bound to its hash)
	SealDevice  = "device"  // an approved device code (bound to its hash)
	SealCIBA    = "ciba"    // an approved CIBA request (bound to its hash, Plan 41c)
	SealConsent = "consent" // a consent transaction (bound to session and client)
)

// sealedEffects is the part of Effects that outlives the flow: claims and
// scope edits. Consent also retains deletion keys for deferred invitation
// defaults; metadata values commit when the flow ends. Transaction metadata
// never leaves the flow.
type sealedEffects struct {
	FlowExecuted    bool            `json:"flow_executed,omitempty"`
	Session         *SessionEffects `json:"session,omitempty"`
	PrimaryUserID   string          `json:"primary_user_id,omitempty"`
	RecordedMethods []string        `json:"recorded_methods,omitempty"`
	// Only explicit deletion keys survive consent to suppress deferred invitation defaults.
	DeletedAppMetadata  []string       `json:"deleted_app_metadata,omitempty"`
	DeletedUserMetadata []string       `json:"deleted_user_metadata,omitempty"`
	MFA                 *MFAEffects    `json:"mfa,omitempty"`
	RBAC                *RBACSnapshot  `json:"rbac,omitempty"`
	AccessClaims        map[string]any `json:"access_claims,omitempty"`
	IDClaims            map[string]any `json:"id_claims,omitempty"`
	AddScopes           []string       `json:"add_scopes,omitempty"`
	RemoveScopes        []string       `json:"remove_scopes,omitempty"`
	Target              *[]string      `json:"target,omitempty"`
	Ceiling             *[]string      `json:"ceiling,omitempty"`
	// SAML carries api.samlResponse.* settings across MFA and consent (Plan 37a).
	SAML *actionresult.SAMLEffects `json:"saml,omitempty"`
}

// SealEffects envelope-encrypts e's token effects (custom claims may be
// sensitive) under the master key, bound to the tenant, the purpose and
// the bind values. A nil e seals an empty set.
func SealEffects(w keys.Wrapper, tenantID, purpose string, e *Effects, bind ...string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("actions: a master key wrapper is required to seal Action effects")
	}
	var s sealedEffects
	if e != nil {
		s = sealedEffects{AccessClaims: e.AccessClaims, IDClaims: e.IDClaims, AddScopes: e.AddScopes, RemoveScopes: e.RemoveScopes, RBAC: e.RBAC, SAML: e.SAML}
		if purpose == SealConsent {
			s.FlowExecuted = e.FlowExecuted
			s.MFA = e.MFA
			s.Session, s.PrimaryUserID, s.RecordedMethods = e.Session, e.PrimaryUserID, e.RecordedMethods
			for k, v := range e.AppMetadata {
				if v == nil {
					s.DeletedAppMetadata = append(s.DeletedAppMetadata, k)
				}
			}
			for k, v := range e.UserMetadata {
				if v == nil {
					s.DeletedUserMetadata = append(s.DeletedUserMetadata, k)
				}
			}
		}
		if e.Target != nil {
			t := append([]string{}, e.Target.Scopes...)
			s.Target = &t
		}
		if e.Ceiling != nil {
			c := append([]string{}, e.Ceiling...)
			s.Ceiling = &c
		}
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("actions: encoding effects: %w", err)
	}
	return keys.SealBound(w, effectsLabel, append([]string{tenantID, purpose}, bind...), plain)
}

// OpenEffects reverses SealEffects under the same tenant, purpose and bind
// values.
func OpenEffects(w keys.Wrapper, tenantID, purpose string, sealed []byte, bind ...string) (*Effects, error) {
	if w == nil {
		return nil, errors.New("actions: a master key wrapper is required to open Action effects")
	}
	plain, err := keys.OpenBound(w, effectsLabel, append([]string{tenantID, purpose}, bind...), sealed)
	if err != nil {
		return nil, err
	}
	var s sealedEffects
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, fmt.Errorf("actions: decoding effects: %w", err)
	}
	e := &Effects{MFA: s.MFA, AccessClaims: s.AccessClaims, IDClaims: s.IDClaims, AddScopes: s.AddScopes, RemoveScopes: s.RemoveScopes, RBAC: s.RBAC, SAML: s.SAML}
	if purpose == SealConsent {
		e.FlowExecuted = s.FlowExecuted
		e.Session, e.PrimaryUserID, e.RecordedMethods = s.Session, s.PrimaryUserID, s.RecordedMethods
		if len(s.DeletedAppMetadata) > 0 {
			e.AppMetadata = map[string]any{}
			for _, k := range s.DeletedAppMetadata {
				e.AppMetadata[k] = nil
			}
		}
		if len(s.DeletedUserMetadata) > 0 {
			e.UserMetadata = map[string]any{}
			for _, k := range s.DeletedUserMetadata {
				e.UserMetadata[k] = nil
			}
		}
	}
	if s.Target != nil {
		e.Target = &TargetEdit{Scopes: *s.Target}
	}
	if s.Ceiling != nil {
		e.Ceiling = *s.Ceiling
	}
	return e, nil
}

// CeilingOf is a refresh family's ceiling (spec §7): the issued scopes,
// which already reflect the Actions' target-scope edits, consent and
// policy, minus the Actions' target additions (scopes not in before, the
// set authorized before the flow ran). Removed scopes stay out.
func CeilingOf(issued, before []string) []string {
	out := []string{}
	for _, s := range issued {
		if slices.Contains(before, s) {
			out = append(out, s)
		}
	}
	return out
}
