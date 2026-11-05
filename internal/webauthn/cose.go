package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// PublicKey is a parsed COSE_Key (RFC 9052/9053, RFC 8230) with its
// algorithm.
type PublicKey struct {
	Alg int64
	Key crypto.PublicKey
}

// COSE algorithm identifiers zeroauthy verifies.
const (
	AlgES256 int64 = -7
	AlgES384 int64 = -35
	AlgES512 int64 = -36
	AlgEdDSA int64 = -8
	AlgRS256 int64 = -257
	AlgPS256 int64 = -37
)

// ParseCOSEKey parses a public COSE_Key. Private parameters and unknown
// labels are refused, as are off-curve points, RSA moduli outside 2048–8192
// bits and even or tiny RSA exponents.
func ParseCOSEKey(raw []byte) (PublicKey, error) {
	if len(raw) == 0 {
		return PublicKey{}, fail("key", "empty COSE key")
	}
	if len(raw) > webauthnrules.Limits.COSEMax {
		return PublicKey{}, fail("too_large", "COSE key over %d bytes", webauthnrules.Limits.COSEMax)
	}
	v, err := DecodeCBOR(raw, 2, 16)
	if err != nil {
		return PublicKey{}, fail("key", "COSE key is not valid CBOR")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return PublicKey{}, fail("key", "COSE key is not a map")
	}
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)
	allowed := map[int64]bool{1: true, 3: true, -1: true, -2: true}
	if kty == 2 {
		allowed[-3] = true
	}
	for k := range m {
		label, ok := k.(int64)
		if !ok || !allowed[label] {
			return PublicKey{}, fail("key", "unexpected COSE label")
		}
	}
	bytesAt := func(label int64) []byte { b, _ := m[label].([]byte); return b }
	switch kty {
	case 1: // OKP
		crv, _ := m[int64(-1)].(int64)
		if alg != AlgEdDSA || crv != 6 {
			return PublicKey{}, fail("alg", "OKP key must be Ed25519 with EdDSA")
		}
		x := bytesAt(-2)
		if len(x) != ed25519.PublicKeySize {
			return PublicKey{}, fail("key", "Ed25519 key must be 32 bytes")
		}
		return PublicKey{Alg: alg, Key: ed25519.PublicKey(append([]byte(nil), x...))}, nil
	case 2: // EC2
		crv, _ := m[int64(-1)].(int64)
		curves := map[int64]struct {
			alg   int64
			curve elliptic.Curve
		}{1: {AlgES256, elliptic.P256()}, 2: {AlgES384, elliptic.P384()}, 3: {AlgES512, elliptic.P521()}}
		c, ok := curves[crv]
		if !ok || c.alg != alg {
			return PublicKey{}, fail("alg", "EC2 curve and algorithm do not match")
		}
		n := (c.curve.Params().BitSize + 7) / 8
		x, y := bytesAt(-2), bytesAt(-3)
		if len(x) != n || len(y) != n {
			return PublicKey{}, fail("key", "EC2 coordinates must be %d bytes", n)
		}
		point := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, point)
		if err != nil {
			return PublicKey{}, fail("key", "EC2 point is not on the curve")
		}
		return PublicKey{Alg: alg, Key: pub}, nil
	case 3: // RSA
		if alg != AlgRS256 && alg != AlgPS256 {
			return PublicKey{}, fail("alg", "unsupported RSA algorithm")
		}
		nb, eb := bytesAt(-1), bytesAt(-2)
		mod := new(big.Int).SetBytes(nb)
		if mod.BitLen() < 2048 || mod.BitLen() > 8192 {
			return PublicKey{}, fail("key", "RSA modulus must be 2048 to 8192 bits")
		}
		if len(eb) == 0 || len(eb) > 4 {
			return PublicKey{}, fail("key", "RSA exponent out of range")
		}
		e := new(big.Int).SetBytes(eb).Int64()
		if e < 3 || e%2 == 0 {
			return PublicKey{}, fail("key", "RSA exponent must be odd and at least 3")
		}
		return PublicKey{Alg: alg, Key: &rsa.PublicKey{N: mod, E: int(e)}}, nil
	}
	return PublicKey{}, fail("key", "unsupported COSE key type")
}
