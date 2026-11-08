// Package webauthntest is an in-process software authenticator for tests.
// It creates credentials and assertions as a browser would hand them to a
// relying party (PublicKeyCredential JSON with base64url fields), with knobs
// for every verification failure the verifier must catch. Never use it
// outside tests.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"slices"
	"sort"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

// Options are the authenticator's knobs. Zero values give a well-behaved
// ES256 platform-less authenticator that sets UP and UV.
type Options struct {
	Alg            int64 // COSE algorithm; 0 means ES256
	UV, BE, BS     bool
	NoUP           bool
	Attachment     string // reported authenticatorAttachment
	Format         string // attestation format; "" means "none"
	AttStmt        map[any]any
	SignCount      uint32
	OmitUserHandle bool
	CrossOrigin    bool
	TopOrigin      string
	TamperRPIDHash bool
	ClientDataType string // overrides webauthn.create / webauthn.get
	Tail           []byte // appended to authenticator data
	CredIDLen      int    // credential ID length; 0 means 32
	ExtraFlags     byte   // RFU flag bits to set
	Transports     []string
}

type credential struct {
	id, userHandle []byte
	rpID           string
	alg            int64
	signer         crypto.Signer
}

// Authenticator holds credentials it has created. Opts may be changed
// between calls.
type Authenticator struct {
	Opts  Options
	creds []credential
}

// New returns an authenticator with the given knobs.
func New(opts Options) *Authenticator { return &Authenticator{Opts: opts} }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) alg() int64 {
	if a.Opts.Alg == 0 {
		return webauthn.AlgES256
	}
	return a.Opts.Alg
}

// Create performs a registration ceremony and returns the credential JSON.
func (a *Authenticator) Create(opts webauthn.CreationOptions, origin string) []byte {
	alg := a.alg()
	signer, cose := newKey(alg)
	n := a.Opts.CredIDLen
	if n == 0 {
		n = 32
	}
	id := make([]byte, n)
	_, _ = rand.Read(id)
	a.creds = append(a.creds, credential{id: id, userHandle: slices.Clone(opts.UserID), rpID: opts.RPID, alg: alg, signer: signer})
	attested := make([]byte, 0, 18+len(id)+len(cose))
	attested = append(attested, make([]byte, 16)...) // all-zero AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(id)))
	attested = append(attested, id...)
	attested = append(attested, cose...)
	authData := a.authData(opts.RPID, 0x40, attested)
	format := a.Opts.Format
	if format == "" {
		format = "none"
	}
	stmt := a.Opts.AttStmt
	if stmt == nil {
		stmt = map[any]any{}
		if format != "none" {
			stmt = map[any]any{"alg": int64(-7), "sig": []byte{1, 2, 3}}
		}
	}
	att := cborMap(map[any]any{"fmt": format, "attStmt": stmt, "authData": authData})
	resp := map[string]any{
		"clientDataJSON":    b64(a.clientData("webauthn.create", opts.Challenge, origin)),
		"attestationObject": b64(att),
		"transports":        a.Opts.Transports,
	}
	return a.credentialJSON(id, resp)
}

// Get performs an assertion with the first allowed credential, or any
// credential for the RP ID when the allow list is empty (discoverable).
func (a *Authenticator) Get(opts webauthn.RequestOptions, origin string) []byte {
	var c *credential
	for i := range a.creds {
		cr := &a.creds[i]
		if cr.rpID != opts.RPID {
			continue
		}
		if len(opts.Allow) == 0 || slices.ContainsFunc(opts.Allow, func(d webauthn.Descriptor) bool { return slices.Equal(d.ID, cr.id) }) {
			c = cr
			break
		}
	}
	if c == nil {
		panic("webauthntest: no credential for " + opts.RPID)
	}
	authData := a.authData(opts.RPID, 0, nil)
	clientData := a.clientData("webauthn.get", opts.Challenge, origin)
	sum := sha256.Sum256(clientData)
	sig := sign(c.signer, c.alg, append(slices.Clone(authData), sum[:]...))
	resp := map[string]any{
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
		"userHandle":        nil,
	}
	if !a.Opts.OmitUserHandle {
		resp["userHandle"] = b64(c.userHandle)
	}
	return a.credentialJSON(c.id, resp)
}

func (a *Authenticator) credentialJSON(id []byte, resp map[string]any) []byte {
	out := map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": resp, "clientExtensionResults": map[string]any{}}
	if a.Opts.Attachment != "" {
		out["authenticatorAttachment"] = a.Opts.Attachment
	}
	b, _ := json.Marshal(out)
	return b
}

func (a *Authenticator) clientData(typ string, challenge []byte, origin string) []byte {
	if a.Opts.ClientDataType != "" {
		typ = a.Opts.ClientDataType
	}
	m := map[string]any{"type": typ, "challenge": b64(challenge), "origin": origin, "crossOrigin": a.Opts.CrossOrigin}
	if a.Opts.TopOrigin != "" {
		m["topOrigin"] = a.Opts.TopOrigin
	}
	b, _ := json.Marshal(m)
	return b
}

func (a *Authenticator) authData(rpID string, extra byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	if a.Opts.TamperRPIDHash {
		h[0] ^= 0xff
	}
	flags := extra | a.Opts.ExtraFlags
	if !a.Opts.NoUP {
		flags |= 0x01
	}
	if a.Opts.UV {
		flags |= 0x04
	}
	if a.Opts.BE {
		flags |= 0x08
	}
	if a.Opts.BS {
		flags |= 0x10
	}
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.Opts.SignCount)
	out = append(out, attested...)
	return append(out, a.Opts.Tail...)
}

func newKey(alg int64) (crypto.Signer, []byte) {
	switch alg {
	case webauthn.AlgEdDSA:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return priv, cborMap(map[any]any{int64(1): int64(1), int64(3): alg, int64(-1): int64(6), int64(-2): []byte(pub)})
	case webauthn.AlgES256, webauthn.AlgES384, webauthn.AlgES512:
		curve, crv := map[int64]elliptic.Curve{webauthn.AlgES256: elliptic.P256(), webauthn.AlgES384: elliptic.P384(), webauthn.AlgES512: elliptic.P521()}[alg],
			map[int64]int64{webauthn.AlgES256: 1, webauthn.AlgES384: 2, webauthn.AlgES512: 3}[alg]
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		n := (curve.Params().BitSize + 7) / 8
		x, y := make([]byte, n), make([]byte, n)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		return k, cborMap(map[any]any{int64(1): int64(2), int64(3): alg, int64(-1): crv, int64(-2): x, int64(-3): y})
	case webauthn.AlgRS256, webauthn.AlgPS256:
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		return k, cborMap(map[any]any{int64(1): int64(3), int64(3): alg, int64(-1): k.N.Bytes(), int64(-2): big.NewInt(int64(k.E)).Bytes()})
	}
	panic("webauthntest: unsupported alg")
}

func sign(s crypto.Signer, alg int64, data []byte) []byte {
	switch alg {
	case webauthn.AlgEdDSA:
		return ed25519.Sign(s.(ed25519.PrivateKey), data)
	case webauthn.AlgES256:
		h := sha256.Sum256(data)
		sig, _ := ecdsa.SignASN1(rand.Reader, s.(*ecdsa.PrivateKey), h[:])
		return sig
	case webauthn.AlgES384:
		h := sha512.Sum384(data)
		sig, _ := ecdsa.SignASN1(rand.Reader, s.(*ecdsa.PrivateKey), h[:])
		return sig
	case webauthn.AlgES512:
		h := sha512.Sum512(data)
		sig, _ := ecdsa.SignASN1(rand.Reader, s.(*ecdsa.PrivateKey), h[:])
		return sig
	case webauthn.AlgRS256:
		h := sha256.Sum256(data)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, s.(*rsa.PrivateKey), crypto.SHA256, h[:])
		return sig
	case webauthn.AlgPS256:
		h := sha256.Sum256(data)
		sig, _ := rsa.SignPSS(rand.Reader, s.(*rsa.PrivateKey), crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		return sig
	}
	panic("webauthntest: unsupported alg")
}

// cborMap encodes a map with integer or text keys in deterministic order.
func cborMap(m map[any]any) []byte {
	keys := make([]any, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return string(cbor(keys[i])) < string(cbor(keys[j])) })
	out := cborHead(5, uint64(len(m)))
	for _, k := range keys {
		out = append(out, cbor(k)...)
		out = append(out, cbor(m[k])...)
	}
	return out
}

func cbor(v any) []byte {
	switch x := v.(type) {
	case int64:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case int:
		return cbor(int64(x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case map[any]any:
		return cborMap(x)
	}
	panic("webauthntest: unsupported CBOR value")
}

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
}
