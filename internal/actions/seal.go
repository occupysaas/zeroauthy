package actions

import (
	"encoding/json"
	"errors"
	"fmt"
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
	SealConsent = "consent" // a consent transaction (bound to session and client)
)

// sealedEffects is the part of Effects that outlives the flow: claims and
// scope edits. Metadata is committed (or discarded) when the flow ends and
// transaction metadata never leaves it.
type sealedEffects struct {
	RBAC         *RBACSnapshot  `json:"rbac,omitempty"`
	AccessClaims map[string]any `json:"access_claims,omitempty"`
	IDClaims     map[string]any `json:"id_claims,omitempty"`
	AddScopes    []string       `json:"add_scopes,omitempty"`
	RemoveScopes []string       `json:"remove_scopes,omitempty"`
	Target       *[]string      `json:"target,omitempty"`
	Ceiling      *[]string      `json:"ceiling,omitempty"`
}

// HasTokenEffects reports whether e changes a token: custom claims,
// accessToken scope edits, or a refresh ceiling that differs from the
// issued scopes. A nil e has none.
func (e *Effects) HasTokenEffects() bool {
	return e != nil && (len(e.AccessClaims) > 0 || len(e.IDClaims) > 0 || len(e.AddScopes) > 0 || len(e.RemoveScopes) > 0 ||
		e.Ceiling != nil || e.RBAC != nil)
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
		s = sealedEffects{AccessClaims: e.AccessClaims, IDClaims: e.IDClaims, AddScopes: e.AddScopes, RemoveScopes: e.RemoveScopes, RBAC: e.RBAC}
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
	e := &Effects{AccessClaims: s.AccessClaims, IDClaims: s.IDClaims, AddScopes: s.AddScopes, RemoveScopes: s.RemoveScopes, RBAC: s.RBAC}
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
