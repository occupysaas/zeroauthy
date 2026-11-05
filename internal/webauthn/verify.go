package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Expect holds the relying party's expected values for one ceremony.
type Expect struct {
	Challenge         []byte
	RPID              string
	Origins           []string // exact allowed origins
	RequireUV         bool
	Algs              []int64 // registration only; default DefaultAlgs
	RequireUserHandle bool    // assertion: discoverable (first-factor) logins
}

// Registration is a verified new credential.
type Registration struct {
	CredentialID, PublicKeyCOSE []byte
	Alg                         int64
	AAGUID                      [16]byte
	SignCount                   uint32
	UV, BE, BS                  bool
	Format                      string // always "none" (LR33b-9)
	Transports                  []string
	Attachment                  string
}

// Assertion is a verified authentication.
type Assertion struct {
	CredentialID, UserHandle []byte
	SignCount                uint32
	UV, BE, BS               bool
	Attachment               string
}

// Stored is what the relying party kept for a credential.
type Stored struct {
	PublicKeyCOSE []byte
	SignCount     uint32
	BE            bool
	UserHandle    []byte
}

// knownFormats are accepted without verifying the statement (LR33b-9).
var knownFormats = []string{"packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple"}

func checkFlags(a *authData, e Expect) error {
	if subtle.ConstantTimeCompare(a.rpIDHash, rpIDHash(e.RPID)) != 1 {
		return fail("rp_id", "rpIdHash does not match")
	}
	if !a.up() {
		return fail("user_present", "user presence flag clear")
	}
	if e.RequireUV && !a.uv() {
		return fail("user_verified", "user verification flag clear")
	}
	if a.bs() && !a.be() {
		return fail("backup_state", "backup state without backup eligibility")
	}
	return nil
}

func rpIDHash(rpID string) []byte { h := sha256.Sum256([]byte(rpID)); return h[:] }

// VerifyRegistration checks a registration (spec §4.3).
func VerifyRegistration(c *Credential, e Expect) (*Registration, error) {
	if c.Type != "public-key" {
		return nil, fail("type", "credential type %q", c.Type)
	}
	if err := checkClientData(c.ClientDataJSON, "webauthn.create", e); err != nil {
		return nil, err
	}
	if len(c.AttestationObject) > webauthnrules.Limits.AttestationMax {
		return nil, fail("too_large", "attestation object too large")
	}
	v, err := DecodeCBOR(c.AttestationObject, webauthnrules.Limits.CBORDepth, webauthnrules.Limits.CBORItems)
	if err != nil {
		return nil, err
	}
	att, _ := v.(map[any]any)
	format, _ := att["fmt"].(string)
	stmt, okStmt := att["attStmt"].(map[any]any)
	rawAuth, _ := att["authData"].([]byte)
	if att == nil || format == "" || !okStmt || rawAuth == nil {
		return nil, fail("parse", "attestation object is malformed")
	}
	a, err := parseAuthData(rawAuth)
	if err != nil {
		return nil, err
	}
	if err := checkFlags(a, e); err != nil {
		return nil, err
	}
	if a.credID == nil {
		return nil, fail("parse", "no attested credential data")
	}
	if !bytes.Equal(a.credID, c.RawID) {
		return nil, fail("parse", "credential ID does not match rawId")
	}
	key, err := ParseCOSEKey(a.cose)
	if err != nil {
		return nil, err
	}
	algs := e.Algs
	if len(algs) == 0 {
		algs = DefaultAlgs
	}
	if !slices.Contains(algs, key.Alg) {
		return nil, fail("alg", "algorithm %d not offered", key.Alg)
	}
	switch {
	case format == "none":
		if len(stmt) != 0 {
			return nil, fail("attestation", "format none with a statement")
		}
	case slices.Contains(knownFormats, format):
	default:
		return nil, fail("attestation", "unknown attestation format")
	}
	return &Registration{
		CredentialID: slices.Clone(a.credID), PublicKeyCOSE: slices.Clone(a.cose), Alg: key.Alg, AAGUID: a.aaguid,
		SignCount: a.signCount, UV: a.uv(), BE: a.be(), BS: a.bs(), Format: "none",
		Transports: slices.Clone(c.Transports), Attachment: c.Attachment,
	}, nil
}

// VerifyAssertion checks an assertion against a stored credential (§4.4).
func VerifyAssertion(c *Credential, e Expect, s Stored) (*Assertion, error) {
	if c.Type != "public-key" {
		return nil, fail("type", "credential type %q", c.Type)
	}
	if err := checkClientData(c.ClientDataJSON, "webauthn.get", e); err != nil {
		return nil, err
	}
	a, err := parseAuthData(c.AuthenticatorData)
	if err != nil {
		return nil, err
	}
	if err := checkFlags(a, e); err != nil {
		return nil, err
	}
	if e.RequireUserHandle && c.UserHandle == nil || c.UserHandle != nil && subtle.ConstantTimeCompare(c.UserHandle, s.UserHandle) != 1 {
		return nil, fail("user_handle", "user handle does not match")
	}
	key, err := ParseCOSEKey(s.PublicKeyCOSE)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.ClientDataJSON)
	if !verifySignature(key, append(slices.Clone(c.AuthenticatorData), sum[:]...), c.Signature) {
		return nil, fail("signature", "signature does not verify")
	}
	if (s.SignCount != 0 || a.signCount != 0) && a.signCount <= s.SignCount {
		return nil, fail("sign_count", "sign count did not increase")
	}
	if a.be() != s.BE {
		return nil, fail("backup_eligibility", "backup eligibility changed")
	}
	return &Assertion{CredentialID: slices.Clone(c.RawID), UserHandle: slices.Clone(c.UserHandle), SignCount: a.signCount,
		UV: a.uv(), BE: a.be(), BS: a.bs(), Attachment: c.Attachment}, nil
}

func verifySignature(k PublicKey, data, sig []byte) bool {
	switch k.Alg {
	case AlgEdDSA:
		return ed25519.Verify(k.Key.(ed25519.PublicKey), data, sig)
	case AlgES256:
		h := sha256.Sum256(data)
		return ecdsa.VerifyASN1(k.Key.(*ecdsa.PublicKey), h[:], sig)
	case AlgES384:
		h := sha512.Sum384(data)
		return ecdsa.VerifyASN1(k.Key.(*ecdsa.PublicKey), h[:], sig)
	case AlgES512:
		h := sha512.Sum512(data)
		return ecdsa.VerifyASN1(k.Key.(*ecdsa.PublicKey), h[:], sig)
	case AlgRS256:
		h := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(k.Key.(*rsa.PublicKey), crypto.SHA256, h[:], sig) == nil
	case AlgPS256:
		h := sha256.Sum256(data)
		return rsa.VerifyPSS(k.Key.(*rsa.PublicKey), crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return false
}
