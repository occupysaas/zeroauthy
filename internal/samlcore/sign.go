package samlcore

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // SAML thumbprints and opt-in RSA-SHA1 (D-0130).
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	dsig "github.com/zeroauthy/zeroauthy/internal/third_party/goxmldsig"
)

// Signature and digest algorithm names, as Auth0 configures them.
const (
	AlgRSASHA256 = "rsa-sha256"
	AlgRSASHA384 = "rsa-sha384"
	AlgRSASHA512 = "rsa-sha512"
	AlgRSASHA1   = "rsa-sha1"
	DigestSHA256 = "sha256"
	DigestSHA384 = "sha384"
	DigestSHA512 = "sha512"
	DigestSHA1   = "sha1"
)

var signatureMethods = map[string]string{
	AlgRSASHA256: dsig.RSASHA256SignatureMethod,
	AlgRSASHA384: dsig.RSASHA384SignatureMethod,
	AlgRSASHA512: dsig.RSASHA512SignatureMethod,
	AlgRSASHA1:   dsig.RSASHA1SignatureMethod,
}

var digestHashes = map[string]crypto.Hash{
	DigestSHA256: crypto.SHA256, DigestSHA384: crypto.SHA384, DigestSHA512: crypto.SHA512, DigestSHA1: crypto.SHA1,
}

// SignatureMethodURI returns the XML-DSig URI of an Auth0 algorithm name.
func SignatureMethodURI(alg string) (string, bool) {
	if alg == "" {
		alg = AlgRSASHA256
	}
	uri, ok := signatureMethods[alg]
	return uri, ok
}

// Signer signs SAML elements with an enveloped XML signature. Algorithm and
// Digest default to RSA-SHA256 and SHA-256.
type Signer struct {
	Key       crypto.Signer
	Cert      *x509.Certificate
	Algorithm string
	Digest    string
}

func (s Signer) context() (*dsig.SigningContext, error) {
	if s.Key == nil || s.Cert == nil {
		return nil, errorf("signer needs a key and a certificate")
	}
	method, ok := SignatureMethodURI(s.Algorithm)
	if !ok {
		return nil, errorf("unsupported signature algorithm")
	}
	digest := s.Digest
	if digest == "" {
		digest = DigestSHA256
	}
	hash, ok := digestHashes[digest]
	if !ok {
		return nil, errorf("unsupported digest algorithm")
	}
	ctx, err := dsig.NewSigningContext(s.Key, [][]byte{s.Cert.Raw})
	if err != nil {
		return nil, errorf("signing context: %v", err)
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		return nil, errorf("signature method does not match the key")
	}
	ctx.DigestHash = hash
	ctx.IdAttribute = dsig.DefaultIdAttr
	ctx.Prefix = "ds"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return ctx, nil
}

// SignEnveloped returns a signed copy of el, which must carry an ID and
// declare the namespaces it uses itself (build elements standalone, sign,
// then embed). The Signature follows the element's Issuer, as the SAML
// schemas require, or comes first when there is no Issuer.
func (s Signer) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	if el == nil || el.SelectAttrValue(dsig.DefaultIdAttr, "") == "" {
		return nil, errorf("element to sign has no ID")
	}
	ctx, err := s.context()
	if err != nil {
		return nil, err
	}
	signed, err := ctx.SignEnveloped(el.Copy())
	if err != nil {
		return nil, errorf("signing failed")
	}
	// goxmldsig appends the Signature without setting its parent, so remove
	// it by slot rather than with RemoveChild.
	kids := signed.ChildElements()
	sig := kids[len(kids)-1]
	for i := len(signed.Child) - 1; i >= 0; i-- {
		if signed.Child[i] == etree.Token(sig) {
			signed.Child = append(signed.Child[:i], signed.Child[i+1:]...)
			break
		}
	}
	at := 0
	if first := signed.ChildElements(); len(first) > 0 && first[0].Tag == "Issuer" {
		at = first[0].Index() + 1
	}
	signed.InsertChildAt(at, sig)
	return signed, nil
}

// SignBytes signs raw bytes (the HTTP-Redirect binding's signed query).
func (s Signer) SignBytes(content []byte) ([]byte, error) {
	ctx, err := s.context()
	if err != nil {
		return nil, err
	}
	out, err := ctx.SignString(string(content))
	if err != nil {
		return nil, errorf("signing failed")
	}
	return out, nil
}

// Thumbprints returns the lowercase hex SHA-1 and SHA-384 thumbprints of a
// certificate, as Auth0 computes thumbprints and thumbprints_sha384.
func Thumbprints(cert *x509.Certificate) (string, string) {
	s1 := sha1.Sum(cert.Raw) //nolint:gosec // thumbprint identifier, not a security hash here.
	s384 := sha512.Sum384(cert.Raw)
	return hex.EncodeToString(s1[:]), hex.EncodeToString(s384[:])
}
