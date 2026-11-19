package federation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func encryptFixture(t *testing.T, pub any, kid, alg, enc, plain string) string {
	t.Helper()
	if alg != "RSA-OAEP-384" && alg != "RSA-OAEP-512" {
		encrypter, e := jose.NewEncrypter(jose.ContentEncryption(enc), jose.Recipient{Algorithm: jose.KeyAlgorithm(alg), Key: pub, KeyID: kid}, nil)
		if e != nil {
			t.Fatal(e)
		}
		obj, e := encrypter.Encrypt([]byte(plain))
		if e != nil {
			t.Fatal(e)
		}
		raw, e := obj.CompactSerialize()
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	// Independent RFC 7516 compact fixture for OAEP variants missing from go-jose.
	h, _ := json.Marshal(map[string]string{"alg": alg, "enc": enc, "kid": kid})
	b64 := base64.RawURLEncoding.EncodeToString
	protected := b64(h)
	cek := make([]byte, 32)
	rand.Read(cek)
	var iv, ct, tag []byte
	if enc == "A256GCM" {
		iv = make([]byte, 12)
		rand.Read(iv)
		block, _ := aes.NewCipher(cek)
		g, _ := cipher.NewGCM(block)
		sealed := g.Seal(nil, iv, []byte(plain), []byte(protected))
		ct, tag = sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	} else {
		iv = make([]byte, 16)
		rand.Read(iv)
		block, _ := aes.NewCipher(cek[16:])
		padding := 16 - len(plain)%16
		padded := append([]byte(plain), bytes.Repeat([]byte{byte(padding)}, padding)...)
		ct = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		mac := hmac.New(sha256.New, cek[:16])
		mac.Write([]byte(protected))
		mac.Write(iv)
		mac.Write(ct)
		var al [8]byte
		binary.BigEndian.PutUint64(al[:], uint64(len(protected))*8)
		mac.Write(al[:])
		tag = mac.Sum(nil)[:16]
	}
	hash := sha512.New384()
	if alg == "RSA-OAEP-512" {
		hash = sha512.New()
	}
	wrapped, e := rsa.EncryptOAEP(hash, rand.Reader, pub.(*rsa.PublicKey), cek, nil)
	if e != nil {
		t.Fatal(e)
	}
	return strings.Join([]string{protected, b64(wrapped), b64(iv), b64(ct), b64(tag)}, ".")
}
func TestJWEAccept(t *testing.T) {
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{17}, 32))
	conn := &store.Connection{TenantID: "t", ID: "c"}
	for _, alg := range rules.EncryptionAlgorithms {
		for _, enc := range []string{"A256GCM", "A128CBC-HS256"} {
			t.Run(alg+"/"+enc, func(t *testing.T) {
				k, e := GenerateConnectionKey(w, conn, "encryption", alg, "login.example", fixedTime)
				if e != nil {
					t.Fatal(e)
				}
				cert, e := x509.ParseCertificate(k.CertDER)
				if e != nil {
					t.Fatal(e)
				}
				raw := encryptFixture(t, cert.PublicKey, k.KID, alg, enc, "nested-jws")
				for _, state := range []string{"current", "previous"} {
					k.State = state
					got, e := decryptIDToken(raw, []*store.ConnectionKey{k}, func(k *store.ConnectionKey) (crypto.Signer, error) { return OpenConnectionKey(w, k) }, alg, []string{enc})
					if e != nil || got != "nested-jws" {
						t.Fatal(got, e)
					}
				}
			})
		}
	}
}
func TestJWERefuse(t *testing.T) {
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{18}, 32))
	k, e := GenerateConnectionKey(w, &store.Connection{TenantID: "t", ID: "c"}, "encryption", "RSA-OAEP-256", "login.example", fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	k.State = "current"
	cert, _ := x509.ParseCertificate(k.CertDER)
	raw := encryptFixture(t, cert.PublicKey, k.KID, "RSA-OAEP-256", "A256GCM", "nested-jws")
	open := func(k *store.ConnectionKey) (crypto.Signer, error) { return OpenConnectionKey(w, k) }
	for _, tc := range []struct {
		raw, alg string
		encs     []string
		keys     []*store.ConnectionKey
	}{{"plain-jws", "RSA-OAEP-256", nil, []*store.ConnectionKey{k}}, {raw, "", nil, []*store.ConnectionKey{k}}, {raw, "RSA-OAEP-256", []string{"A128GCM"}, []*store.ConnectionKey{k}}, {raw, "RSA-OAEP-256", nil, nil}} {
		if _, e := decryptIDToken(tc.raw, tc.keys, open, tc.alg, tc.encs); e == nil || strings.Contains(e.Error(), raw) {
			t.Fatal("accepted invalid JWE or exposed token", e)
		}
	}
}

func TestJWEValidationPipeline(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		encrypted, configured, unsigned, bad bool
	}{{"valid", true, true, false, false}, {"unsigned nested", true, true, true, true}, {"plain when configured", false, true, false, true}, {"encrypted when unconfigured", true, false, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			ps := p.providers()
			in := p.exchangeInput(t, ps)
			w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{19}, 32))
			k, e := GenerateConnectionKey(w, &store.Connection{TenantID: "ten", ID: "con"}, "encryption", "RSA-OAEP-256", "login.example", fixedTime)
			if e != nil {
				t.Fatal(e)
			}
			k.State = "current"
			cert, _ := x509.ParseCertificate(k.CertDER)
			nested := p.idToken()
			if tc.unsigned {
				b64 := base64.RawURLEncoding.EncodeToString
				nested = b64([]byte(`{"alg":"none"}`)) + "." + b64([]byte(`{"sub":"attacker"}`)) + "."
			}
			raw := nested
			if tc.encrypted {
				raw = encryptFixture(t, cert.PublicKey, k.KID, "RSA-OAEP-256", "A256GCM", nested)
			}
			if tc.configured {
				in.Config.EncAlg = "RSA-OAEP-256"
				in.DecryptIDToken = func(raw string) (string, error) {
					return decryptIDToken(raw, []*store.ConnectionKey{k}, func(k *store.ConnectionKey) (crypto.Signer, error) { return OpenConnectionKey(w, k) }, in.Config.EncAlg, nil)
				}
			}
			_, e = ps.validateIDToken(context.Background(), in, in.Endpoints, TokenSet{IDToken: raw})
			if (e != nil) != tc.bad {
				t.Fatal(e)
			}
			if e != nil && strings.Contains(e.Error(), raw) {
				t.Fatal("token leaked")
			}
		})
	}
}
