package samlcore

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	dsig "github.com/zeroauthy/zeroauthy/internal/third_party/goxmldsig"
)

// Binding parameter names.
const (
	ParamRequest  = "SAMLRequest"
	ParamResponse = "SAMLResponse"
)

var redirectSigAlgs = map[string]x509.SignatureAlgorithm{
	dsig.RSASHA256SignatureMethod: x509.SHA256WithRSA,
	dsig.RSASHA384SignatureMethod: x509.SHA384WithRSA,
	dsig.RSASHA512SignatureMethod: x509.SHA512WithRSA,
	dsig.RSASHA1SignatureMethod:   x509.SHA1WithRSA,
}

func xmlBytes(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	return doc.WriteToBytes()
}

// EncodeRedirect returns endpoint with the HTTP-Redirect binding parameters
// (deflated, base64, optionally signed) appended to its query.
func EncodeRedirect(endpoint, param string, el *etree.Element, relayState string, signer *Signer) (string, error) {
	if param != ParamRequest && param != ParamResponse {
		return "", errorf("unknown binding parameter")
	}
	raw, err := xmlBytes(el)
	if err != nil {
		return "", errorf("serialize message")
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(raw); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if signer != nil {
		uri, ok := SignatureMethodURI(signer.Algorithm)
		if !ok {
			return "", errorf("unsupported signature algorithm")
		}
		q += "&SigAlg=" + url.QueryEscape(uri)
		sig, err := signer.SignBytes([]byte(q))
		if err != nil {
			return "", err
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + q, nil
}

// RedirectMessage is a decoded HTTP-Redirect binding message.
type RedirectMessage struct {
	Param, RelayState, SigAlg string
	Doc                       *etree.Document
	signature, signedOctets   []byte
}

// Signed reports whether the message carried a signature.
func (m *RedirectMessage) Signed() bool { return len(m.signature) > 0 }

// DecodeRedirect reads the binding parameters from a raw query string. The
// signed octets are kept exactly as received (SAML Bindings §3.4.4.1).
func DecodeRedirect(rawQuery string) (*RedirectMessage, error) {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		name, value, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(name)
		if err != nil {
			return nil, ErrMalformed
		}
		switch key {
		case ParamRequest, ParamResponse, "RelayState", "SigAlg", "Signature":
			if _, dup := raw[key]; dup {
				return nil, ErrMalformed
			}
			raw[key] = value
		}
	}
	m := &RedirectMessage{}
	_, req := raw[ParamRequest]
	_, resp := raw[ParamResponse]
	switch {
	case req && !resp:
		m.Param = ParamRequest
	case resp && !req:
		m.Param = ParamResponse
	default:
		return nil, ErrMalformed
	}
	unesc := func(k string) (string, error) { return url.QueryUnescape(raw[k]) }
	value, err := unesc(m.Param)
	if err != nil {
		return nil, ErrMalformed
	}
	compressed, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil {
		return nil, ErrMalformed
	}
	xmlDoc, err := inflate(compressed)
	if err != nil {
		return nil, err
	}
	if m.Doc, err = Parse(xmlDoc); err != nil {
		return nil, err
	}
	if m.RelayState, err = unesc("RelayState"); err != nil {
		return nil, ErrMalformed
	}
	if sig, ok := raw["Signature"]; ok {
		if m.SigAlg, err = unesc("SigAlg"); err != nil || m.SigAlg == "" {
			return nil, ErrMalformed
		}
		s, err := url.QueryUnescape(sig)
		if err != nil {
			return nil, ErrMalformed
		}
		if m.signature, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err != nil {
			return nil, ErrMalformed
		}
		octets := m.Param + "=" + raw[m.Param]
		if rs, ok := raw["RelayState"]; ok {
			octets += "&RelayState=" + rs
		}
		octets += "&SigAlg=" + raw["SigAlg"]
		m.signedOctets = []byte(octets)
	}
	return m, nil
}

// inflate decompresses a raw DEFLATE stream with the input size limit. A
// message the sender did not deflate (Auth0's deflate: false) is accepted
// when it is plainly XML.
func inflate(compressed []byte) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), MaxInputBytes+1))
	if err == nil {
		if len(out) > MaxInputBytes {
			return nil, ErrTooLarge
		}
		return out, nil
	}
	if trimmed := bytes.TrimSpace(compressed); len(trimmed) > 0 && trimmed[0] == '<' {
		if len(compressed) > MaxInputBytes {
			return nil, ErrTooLarge
		}
		return compressed, nil
	}
	return nil, ErrMalformed
}

// Verify checks the HTTP-Redirect signature against the pinned certificates.
func (m *RedirectMessage) Verify(t Trust) error {
	if !m.Signed() {
		return ErrUnsigned
	}
	alg, ok := redirectSigAlgs[m.SigAlg]
	if !ok {
		return ErrSignature
	}
	if alg == x509.SHA1WithRSA && !t.AllowSHA1 {
		return ErrWeakAlg
	}
	for _, cert := range t.Certs {
		if cert.CheckSignature(alg, m.signedOctets, m.signature) == nil {
			return nil
		}
	}
	return ErrSignature
}

// EncodePOST returns the base64 HTTP-POST binding value of el.
func EncodePOST(el *etree.Element) string {
	raw, err := xmlBytes(el)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodePOST reads an HTTP-POST binding value.
func DecodePOST(value string) (*etree.Document, error) {
	value = strings.Join(strings.Fields(value), "")
	if base64.StdEncoding.DecodedLen(len(value)) > MaxInputBytes+3 {
		return nil, ErrTooLarge
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrMalformed
	}
	return Parse(raw)
}
