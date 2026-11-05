package webauthn

import (
	"crypto/subtle"
	"encoding/json"
	"slices"
	"unicode/utf8"
)

type clientData struct {
	Type        string           `json:"type"`
	Challenge   string           `json:"challenge"`
	Origin      string           `json:"origin"`
	CrossOrigin *bool            `json:"crossOrigin"`
	TopOrigin   *json.RawMessage `json:"topOrigin"`
}

// checkClientData verifies type, challenge (constant time), exact origin,
// and refuses crossOrigin true or any topOrigin (no ceremonies in frames).
func checkClientData(raw []byte, wantType string, e Expect) error {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return fail("parse", "client data is not UTF-8")
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fail("parse", "client data is not JSON")
	}
	if cd.Type != wantType {
		return fail("type", "client data type %q", cd.Type)
	}
	got, err := b64url(cd.Challenge)
	if err != nil || len(e.Challenge) == 0 || subtle.ConstantTimeCompare(got, e.Challenge) != 1 {
		return fail("challenge", "challenge does not match")
	}
	if !slices.Contains(e.Origins, cd.Origin) {
		return fail("origin", "origin not allowed")
	}
	if (cd.CrossOrigin != nil && *cd.CrossOrigin) || cd.TopOrigin != nil {
		return fail("cross_origin", "cross-origin ceremony refused")
	}
	return nil
}
