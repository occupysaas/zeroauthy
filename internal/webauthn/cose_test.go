package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func pad(b []byte, n int) []byte { return append(bytes.Repeat([]byte{0}, n-len(b)), b...) }

func ec2Key(t *testing.T, curve elliptic.Curve, crv, alg int64) (cmap, *ecdsa.PrivateKey) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := (curve.Params().BitSize + 7) / 8
	return cmap{{1, 2}, {3, alg}, {-1, crv}, {-2, pad(k.X.Bytes(), n)}, {-3, pad(k.Y.Bytes(), n)}}, k
}

func TestCOSEKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if k, err := ParseCOSEKey(enc(cmap{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}})); err != nil || k.Alg != -8 || !bytes.Equal(k.Key.(ed25519.PublicKey), pub) {
		t.Fatalf("Ed25519 = %+v %v", k, err)
	}
	for _, c := range []struct {
		curve    elliptic.Curve
		crv, alg int64
	}{{elliptic.P256(), 1, -7}, {elliptic.P384(), 2, -35}, {elliptic.P521(), 3, -36}} {
		m, priv := ec2Key(t, c.curve, c.crv, c.alg)
		k, err := ParseCOSEKey(enc(m))
		if err != nil || k.Alg != c.alg || !k.Key.(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
			t.Fatalf("EC2 alg %d = %+v %v", c.alg, k, err)
		}
		off := append(cmap{}, m...)
		y := append([]byte{}, off[4][1].([]byte)...)
		y[len(y)-1] ^= 1
		off[4] = [2]any{-3, y}
		if _, err := ParseCOSEKey(enc(off)); Reason(err) != "key" {
			t.Errorf("off-curve alg %d reason %q", c.alg, Reason(err))
		}
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(rk.E)).Bytes()
	for _, alg := range []int64{-257, -37} {
		k, err := ParseCOSEKey(enc(cmap{{1, 3}, {3, alg}, {-1, rk.N.Bytes()}, {-2, e}}))
		if err != nil || k.Alg != alg || !k.Key.(*rsa.PublicKey).Equal(&rk.PublicKey) {
			t.Fatalf("RSA alg %d = %+v %v", alg, k, err)
		}
	}
	modulus := func(bits int) []byte {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		return n.Or(n, big.NewInt(1)).Bytes()
	}
	refused := map[string][]byte{
		"rsa 2047 bits":      enc(cmap{{1, 3}, {3, -257}, {-1, modulus(2047)}, {-2, e}}),
		"rsa 8193 bits":      enc(cmap{{1, 3}, {3, -257}, {-1, modulus(8193)}, {-2, e}}),
		"rsa even exponent":  enc(cmap{{1, 3}, {3, -257}, {-1, rk.N.Bytes()}, {-2, []byte{4}}}),
		"private label -4":   enc(cmap{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}, {-4, []byte{1}}}),
		"ed25519 wrong size": enc(cmap{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte{1, 2}}}),
		"unknown kty":        enc(cmap{{1, 9}, {3, -7}}),
		"alg mismatch":       enc(cmap{{1, 1}, {3, -7}, {-1, 6}, {-2, []byte(pub)}}),
	}
	for name, raw := range refused {
		if _, err := ParseCOSEKey(raw); err == nil || (Reason(err) != "key" && Reason(err) != "alg") {
			t.Errorf("%s: err %v reason %q", name, err, Reason(err))
		}
	}
	if _, err := ParseCOSEKey(make([]byte, 16<<10+1)); Reason(err) != "too_large" {
		t.Errorf("oversized reason %q", Reason(err))
	}
	if _, err := ParseCOSEKey(nil); Reason(err) != "key" {
		t.Errorf("empty reason %q", Reason(err))
	}
}

func FuzzParseCOSEKey(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.Add(enc(cmap{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}}))
	f.Add(enc(cmap{{1, 2}, {3, -7}, {-1, 1}, {-2, make([]byte, 32)}, {-3, make([]byte, 32)}}))
	f.Add(enc(cmap{{1, 3}, {3, -257}, {-1, make([]byte, 256)}, {-2, []byte{1, 0, 1}}}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseCOSEKey(b) })
}
