package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Descriptor is a PublicKeyCredentialDescriptor.
type Descriptor struct {
	ID         []byte
	Transports []string
}

// DefaultAlgs are the offered algorithms in the documented order.
var DefaultAlgs = []int64{AlgEdDSA, AlgES256, AlgRS256}

// CreationOptions render as PublicKeyCredentialCreationOptionsJSON.
type CreationOptions struct {
	Challenge                     []byte
	RPID, RPName                  string
	UserID                        []byte
	UserName, DisplayName         string
	Algs                          []int64 // default DefaultAlgs
	Attachment                    string  // "", "platform", "cross-platform"
	ResidentKey, UserVerification string
	Exclude                       []Descriptor
	Timeout                       time.Duration
}

// RequestOptions render as PublicKeyCredentialRequestOptionsJSON.
type RequestOptions struct {
	Challenge        []byte
	RPID             string
	UserVerification string
	Allow            []Descriptor
	Timeout          time.Duration
}

type descriptorJSON struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

func descriptors(ds []Descriptor) []descriptorJSON {
	out := make([]descriptorJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, descriptorJSON{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(d.ID), Transports: d.Transports})
	}
	return out
}

// JSON renders the options for navigator.credentials.create (rp.name equals
// rp.id when RPName is empty; attestation is always "none").
func (o CreationOptions) JSON() ([]byte, error) {
	algs := o.Algs
	if len(algs) == 0 {
		algs = DefaultAlgs
	}
	params := make([]map[string]any, 0, len(algs))
	for _, a := range algs {
		params = append(params, map[string]any{"type": "public-key", "alg": a})
	}
	name := o.RPName
	if name == "" {
		name = o.RPID
	}
	display := o.DisplayName
	if display == "" {
		display = o.UserName
	}
	sel := map[string]any{"residentKey": o.ResidentKey, "requireResidentKey": o.ResidentKey == "required", "userVerification": o.UserVerification}
	if o.Attachment != "" {
		sel["authenticatorAttachment"] = o.Attachment
	}
	return json.Marshal(map[string]any{
		"challenge":              base64.RawURLEncoding.EncodeToString(o.Challenge),
		"rp":                     map[string]string{"id": o.RPID, "name": name},
		"user":                   map[string]string{"id": base64.RawURLEncoding.EncodeToString(o.UserID), "name": o.UserName, "displayName": display},
		"pubKeyCredParams":       params,
		"timeout":                o.Timeout.Milliseconds(),
		"excludeCredentials":     descriptors(o.Exclude),
		"authenticatorSelection": sel,
		"attestation":            "none",
	})
}

// JSON renders the options for navigator.credentials.get.
func (o RequestOptions) JSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"challenge":        base64.RawURLEncoding.EncodeToString(o.Challenge),
		"rpId":             o.RPID,
		"timeout":          o.Timeout.Milliseconds(),
		"userVerification": o.UserVerification,
		"allowCredentials": descriptors(o.Allow),
	})
}

// Ceremony names a row of the spec §4.5 parameter table.
type Ceremony int

const (
	CeremonyPasskeyRegister Ceremony = iota // passkey signup and progressive enrollment
	CeremonyLocalEnroll                     // local (this-device) passkey enrollment
	CeremonyPasskeyLogin                    // discoverable passkey login
	CeremonyRoaming                         // webauthn-roaming MFA enroll/challenge
	CeremonyPlatform                        // webauthn-platform MFA enroll/challenge
)

// Params are the WebAuthn options a ceremony uses; EnforceUV says whether
// the server requires the UV flag.
type Params struct {
	UserVerification, ResidentKey, Attachment string
	EnforceUV                                 bool
}

// ParamsFor returns the §4.5 parameters. roamingUV is the security-key
// user verification setting ("" or "discouraged", "preferred", "required").
func ParamsFor(c Ceremony, roamingUV string) Params {
	switch c {
	case CeremonyPasskeyRegister:
		return Params{UserVerification: "preferred", ResidentKey: "required"}
	case CeremonyLocalEnroll:
		return Params{UserVerification: "preferred", ResidentKey: "required", Attachment: "platform"}
	case CeremonyPasskeyLogin:
		return Params{UserVerification: "preferred"}
	case CeremonyRoaming:
		uv := roamingUV
		if uv != "preferred" && uv != "required" {
			uv = "discouraged"
		}
		return Params{UserVerification: uv, ResidentKey: "discouraged", Attachment: "cross-platform", EnforceUV: uv == "required"}
	case CeremonyPlatform:
		return Params{UserVerification: "required", ResidentKey: "discouraged", Attachment: "platform", EnforceUV: true}
	}
	return Params{}
}
