package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Credential is a parsed PublicKeyCredential (registration or assertion).
type Credential struct {
	ID, RawID                                []byte
	Type, Attachment                         string
	ClientDataJSON, AttestationObject        []byte
	AuthenticatorData, Signature, UserHandle []byte
	Transports                               []string
}

type credentialJSON struct {
	ID         string `json:"id"`
	RawID      string `json:"rawId"`
	Type       string `json:"type"`
	Attachment string `json:"authenticatorAttachment"`
	Response   struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		AuthenticatorData string   `json:"authenticatorData"`
		Signature         string   `json:"signature"`
		UserHandle        *string  `json:"userHandle"`
		Transports        []string `json:"transports"`
	} `json:"response"`
}

// maxCredentialJSON bounds the whole JSON document before decoding.
const maxCredentialJSON = 192 << 10

// b64url decodes base64url, tolerating padding.
func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// ParseCredentialJSON parses the documented authn_response shape. id must
// equal rawId; Level 2 browsers may omit authenticatorAttachment,
// transports, clientExtensionResults and userHandle.
func ParseCredentialJSON(raw []byte) (*Credential, error) {
	if len(raw) > maxCredentialJSON {
		return nil, fail("too_large", "credential JSON over %d bytes", maxCredentialJSON)
	}
	var in credentialJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fail("parse", "credential is not JSON")
	}
	c := &Credential{Type: in.Type, Attachment: in.Attachment, Transports: in.Response.Transports}
	fields := []struct {
		src string
		dst *[]byte
		max int
	}{
		{in.ID, &c.ID, webauthnrules.Limits.CredentialIDMax * 2},
		{in.RawID, &c.RawID, webauthnrules.Limits.CredentialIDMax * 2},
		{in.Response.ClientDataJSON, &c.ClientDataJSON, webauthnrules.Limits.ClientDataMax},
		{in.Response.AttestationObject, &c.AttestationObject, webauthnrules.Limits.AttestationMax},
		{in.Response.AuthenticatorData, &c.AuthenticatorData, webauthnrules.Limits.AttestationMax},
		{in.Response.Signature, &c.Signature, 4096},
	}
	for _, f := range fields {
		b, err := b64url(f.src)
		if err != nil {
			return nil, fail("parse", "field is not base64url")
		}
		if len(b) > f.max {
			return nil, fail("too_large", "field over %d bytes", f.max)
		}
		if len(b) > 0 {
			*f.dst = b
		}
	}
	if in.Response.UserHandle != nil && *in.Response.UserHandle != "" {
		h, err := b64url(*in.Response.UserHandle)
		if err != nil || len(h) > 64 {
			return nil, fail("parse", "userHandle is not valid")
		}
		c.UserHandle = h
	}
	if len(c.RawID) == 0 || !bytes.Equal(c.ID, c.RawID) {
		return nil, fail("parse", "id and rawId differ")
	}
	return c, nil
}
