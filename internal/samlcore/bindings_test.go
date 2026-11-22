package samlcore

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRedirectBinding(t *testing.T) {
	sp := newIdentity(t, "sp", time.Now().Add(time.Hour))
	req, _ := BuildAuthnRequest(AuthnRequest{ID: "_r", IssueInstant: t0, Issuer: "urn:sp", Destination: "https://idp/sso", ACSURL: "https://sp/acs", ProtocolBinding: BindingPOST}, "")
	for _, signed := range []bool{false, true} {
		var signer *Signer
		if signed {
			signer = &Signer{Key: sp.key, Cert: sp.cert}
		}
		loc, err := EncodeRedirect("https://idp/sso?tenant=x", ParamRequest, req, "state & more", signer)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(loc)
		if u.Query().Get("tenant") != "x" || (u.Query().Get("Signature") != "") != signed {
			t.Fatalf("redirect URL %s", loc)
		}
		msg, err := DecodeRedirect(u.RawQuery)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Param != ParamRequest || msg.RelayState != "state & more" || msg.Doc.Root().Tag != "AuthnRequest" || msg.Signed() != signed {
			t.Fatalf("decoded %+v", msg)
		}
		if signed {
			if err := msg.Verify(Trust{Certs: []*x509.Certificate{sp.cert}}); err != nil {
				t.Fatal(err)
			}
			tampered, _ := DecodeRedirect(strings.Replace(u.RawQuery, "RelayState=state", "RelayState=other", 1))
			if err := tampered.Verify(Trust{Certs: []*x509.Certificate{sp.cert}}); err == nil {
				t.Fatal("tampered RelayState verified")
			}
			other := newIdentity(t, "other", time.Now().Add(time.Hour))
			if err := msg.Verify(Trust{Certs: []*x509.Certificate{other.cert}}); err == nil {
				t.Fatal("verified against the wrong certificate")
			}
		}
	}
	// A deflate bomb is cut off at the input limit.
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write([]byte("<a>" + strings.Repeat("x", MaxInputBytes*2) + "</a>"))
	w.Close()
	q := ParamRequest + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if _, err := DecodeRedirect(q); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("deflate bomb: %v", err)
	}
	if _, err := DecodeRedirect("SAMLRequest=%%%"); err == nil {
		t.Fatal("bad query accepted")
	}
	if _, err := DecodeRedirect("SAMLRequest=a&SAMLRequest=b"); err == nil {
		t.Fatal("repeated parameter accepted")
	}
}

func TestPOSTBinding(t *testing.T) {
	el := mustRoot(t, assertionXML("_a", "x"))
	doc, err := DecodePOST(EncodePOST(el))
	if err != nil || doc.Root().Tag != "Assertion" {
		t.Fatalf("POST round trip: %v", err)
	}
	if _, err := DecodePOST("!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, err := DecodePOST(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), MaxInputBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized POST: %v", err)
	}
}
