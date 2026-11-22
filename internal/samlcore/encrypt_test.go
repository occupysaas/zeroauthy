package samlcore

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

func TestEncryptedAssertionRoundTrips(t *testing.T) {
	sp := newIdentity(t, "sp", time.Now().Add(time.Hour))
	for _, data := range []string{EncAES128GCM, EncAES256GCM, EncAES128CBC, EncAES256CBC} {
		for _, key := range []string{KeyRSAOAEP, KeyRSAOAEP11SHA256, KeyRSA15} {
			t.Run(data+"/"+key, func(t *testing.T) {
				enc, err := EncryptAssertion(mustRoot(t, assertionXML("_a", "alice@example.test")), sp.cert, data, key)
				if err != nil {
					t.Fatal(err)
				}
				if !inNS(enc, NSAssertion, "EncryptedAssertion") || strings.Contains(serialize(t, enc), "alice@example.test") {
					t.Fatal("not an opaque EncryptedAssertion")
				}
				received := roundTrip(t, enc)
				opened, err := DecryptAssertion(received, sp.key, Decryption{AllowRSA15: key == KeyRSA15})
				if err != nil {
					t.Fatal(err)
				}
				if NameID(opened) != "alice@example.test" {
					t.Fatalf("decrypted NameID %q", NameID(opened))
				}
				if key == KeyRSA15 {
					if _, err := DecryptAssertion(roundTrip(t, enc), sp.key, Decryption{}); !errors.Is(err, ErrWeakAlg) {
						t.Fatalf("RSA-1_5 without opt-in: %v", err)
					}
				}
			})
		}
	}
}

func TestDecryptRefusals(t *testing.T) {
	sp := newIdentity(t, "sp", time.Now().Add(time.Hour))
	other := newIdentity(t, "other", time.Now().Add(time.Hour))
	enc, err := EncryptAssertion(mustRoot(t, assertionXML("_a", "alice@example.test")), sp.cert, EncAES256CBC, KeyRSAOAEP)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(el *etree.Element, path string) *etree.Element {
		c := roundTrip(t, el)
		v := c.FindElement(path)
		raw, _ := base64.StdEncoding.DecodeString(v.Text())
		raw[len(raw)-1] ^= 1
		v.SetText(base64.StdEncoding.EncodeToString(raw))
		return c
	}
	for name, el := range map[string]*etree.Element{
		"cipher text tampered": flip(enc, "./EncryptedData/CipherData/CipherValue"),
		"wrapped key tampered": flip(enc, ".//EncryptedKey/CipherData/CipherValue"),
		"unknown data algorithm": func() *etree.Element {
			c := roundTrip(t, enc)
			c.FindElement("./EncryptedData/EncryptionMethod").CreateAttr("Algorithm", "urn:x")
			return c
		}(),
		"not encrypted": mustRoot(t, assertionXML("_a", "x")),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptAssertion(el, sp.key, Decryption{})
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "padding") || strings.Contains(err.Error(), "authentication") {
				t.Fatalf("error distinguishes failure kinds: %v", err)
			}
		})
	}
	if _, err := DecryptAssertion(roundTrip(t, enc), other.key, Decryption{}); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	// EncryptedKey as a sibling of EncryptedData (referenced by RetrievalMethod).
	c := roundTrip(t, enc)
	ek := c.FindElement(".//EncryptedKey")
	ki := ek.Parent()
	ki.RemoveChild(ek)
	ki.CreateElement("ds:RetrievalMethod").CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey")
	ek.CreateAttr("xmlns:xenc", NSXMLEnc) // a sibling key declares the namespaces it uses
	ek.CreateAttr("xmlns:ds", NSDSig)
	c.AddChild(ek)
	if _, err := DecryptAssertion(roundTrip(t, c), sp.key, Decryption{}); err != nil {
		t.Fatalf("sibling EncryptedKey: %v", err)
	}
}

func TestVerifyResponseEncryptedAssertion(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	sp := newIdentity(t, "sp", time.Now().Add(time.Hour))
	decrypt := func(el *etree.Element) (*etree.Element, error) { return DecryptAssertion(el, sp.key, Decryption{}) }
	trust := Trust{Certs: []*x509.Certificate{idp.cert}}

	signed, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(mustRoot(t, assertionXML("_a", "carol@example.test")))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncryptAssertion(signed, sp.cert, EncAES256GCM, KeyRSAOAEP)
	if err != nil {
		t.Fatal(err)
	}
	raw := responseXML("_r", serialize(t, enc)[strings.Index(serialize(t, enc), "<saml:EncryptedAssertion"):])
	doc, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyResponse(doc, trust, decrypt)
	if err != nil {
		t.Fatal(err)
	}
	if !v.AssertionSigned || NameID(v.Assertion) != "carol@example.test" {
		t.Fatalf("encrypted signed assertion: %+v %q", v, NameID(v.Assertion))
	}
	if _, err := VerifyResponse(doc, trust, nil); err == nil {
		t.Fatal("encrypted assertion accepted without a decryption key")
	}

	// Encrypted but unsigned, in an unsigned response: refused.
	plainEnc, err := EncryptAssertion(mustRoot(t, assertionXML("_u", "admin@example.test")), sp.cert, EncAES256GCM, KeyRSAOAEP)
	if err != nil {
		t.Fatal(err)
	}
	s := serialize(t, plainEnc)
	doc, _ = Parse([]byte(responseXML("_r", s[strings.Index(s, "<saml:EncryptedAssertion"):])))
	if _, err := VerifyResponse(doc, trust, decrypt); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned encrypted assertion: %v", err)
	}
}
