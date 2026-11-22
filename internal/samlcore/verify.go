package samlcore

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	dsig "github.com/zeroauthy/zeroauthy/internal/third_party/goxmldsig"
	"github.com/zeroauthy/zeroauthy/internal/third_party/goxmldsig/etreeutils"
)

// SAML namespaces.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDSig      = dsig.Namespace
)

// Verification errors. Messages never echo document content.
var (
	ErrUnsigned  = errors.New("samlcore: no trusted signature covers the assertion")
	ErrSignature = errors.New("samlcore: invalid or untrusted signature")
	ErrStructure = errors.New("samlcore: message structure refused")
	ErrWeakAlg   = errors.New("samlcore: SHA-1 is not enabled for this connection")
)

// Trust is what a verifier accepts: pinned certificates and/or certificate
// thumbprints (hex, any case, colons ignored). SHA-1 signature and digest
// algorithms are refused unless AllowSHA1. Pinned certificates are trust
// anchors: their validity dates are not checked (D-0130).
type Trust struct {
	Certs          []*x509.Certificate
	Thumbprints    []string
	Thumbprints384 []string
	AllowSHA1      bool
	Now            func() time.Time
}

var allowedTransforms = map[string]bool{
	string(dsig.EnvelopedSignatureAltorithmId):                  true,
	string(dsig.CanonicalXML10ExclusiveAlgorithmId):             true,
	string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId): true,
}

var sha1Methods = map[string]bool{dsig.RSASHA1SignatureMethod: true, "http://www.w3.org/2000/09/xmldsig#sha1": true}

func inNS(el *etree.Element, ns, tag string) bool { return el.Tag == tag && el.NamespaceURI() == ns }

func directChildren(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if inNS(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

func descendants(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		for _, c := range e.ChildElements() {
			if inNS(c, ns, tag) {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(el)
	return out
}

// detach copies el with every namespace it inherits declared on itself.
func detach(el *etree.Element) (*etree.Element, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, ErrStructure
	}
	out, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, ErrStructure
	}
	return out, nil
}

// checkSignatureShape enforces the one signature, one reference to el's own
// ID, enveloped + exclusive c14n only, and the SHA-1 policy.
func checkSignatureShape(el, sig *etree.Element, t Trust) error {
	id := el.SelectAttrValue("ID", "")
	si := directChildren(sig, NSDSig, "SignedInfo")
	if id == "" || len(si) != 1 {
		return ErrStructure
	}
	c14n := directChildren(si[0], NSDSig, "CanonicalizationMethod")
	method := directChildren(si[0], NSDSig, "SignatureMethod")
	refs := directChildren(si[0], NSDSig, "Reference")
	if len(c14n) != 1 || len(method) != 1 || len(refs) != 1 {
		return ErrStructure
	}
	if alg := c14n[0].SelectAttrValue("Algorithm", ""); alg != string(dsig.CanonicalXML10ExclusiveAlgorithmId) && alg != string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId) {
		return ErrStructure
	}
	if refs[0].SelectAttrValue("URI", "") != "#"+id {
		return ErrStructure
	}
	transforms := directChildren(refs[0], NSDSig, "Transforms")
	if len(transforms) != 1 {
		return ErrStructure
	}
	enveloped := false
	for _, tr := range directChildren(transforms[0], NSDSig, "Transform") {
		alg := tr.SelectAttrValue("Algorithm", "")
		if !allowedTransforms[alg] {
			return ErrStructure
		}
		enveloped = enveloped || alg == string(dsig.EnvelopedSignatureAltorithmId)
	}
	digest := directChildren(refs[0], NSDSig, "DigestMethod")
	if !enveloped || len(digest) != 1 {
		return ErrStructure
	}
	if !t.AllowSHA1 && (sha1Methods[method[0].SelectAttrValue("Algorithm", "")] || sha1Methods[digest[0].SelectAttrValue("Algorithm", "")]) {
		return ErrWeakAlg
	}
	return nil
}

func normalizeThumbprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

// roots returns the certificates trusted for this signature: the pinned
// ones, plus the embedded certificate when its thumbprint is pinned.
func roots(sig *etree.Element, t Trust) []*x509.Certificate {
	out := append([]*x509.Certificate(nil), t.Certs...)
	if len(t.Thumbprints) == 0 && len(t.Thumbprints384) == 0 {
		return out
	}
	for _, ki := range directChildren(sig, NSDSig, "KeyInfo") {
		for _, data := range directChildren(ki, NSDSig, "X509Data") {
			for _, c := range directChildren(data, NSDSig, "X509Certificate") {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Text()), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				s1, s384 := Thumbprints(cert)
				for _, want := range t.Thumbprints {
					if normalizeThumbprint(want) == s1 {
						out = append(out, cert)
					}
				}
				for _, want := range t.Thumbprints384 {
					if normalizeThumbprint(want) == s384 {
						out = append(out, cert)
					}
				}
			}
		}
	}
	return out
}

// VerifyEnveloped verifies the single enveloped signature that is a direct
// child of el and references el's ID. It returns the verified element,
// re-parsed from its canonical form: comments are gone and text is joined,
// so values read from it are exactly what was signed. Callers must read only
// from the returned element.
func VerifyEnveloped(el *etree.Element, t Trust) (*etree.Element, error) {
	if el == nil {
		return nil, ErrStructure
	}
	standalone, err := detach(el)
	if err != nil {
		return nil, err
	}
	sigs := directChildren(standalone, NSDSig, "Signature")
	if len(sigs) != 1 || len(descendants(standalone, NSDSig, "Signature")) != 1 {
		return nil, ErrStructure
	}
	if err := checkSignatureShape(standalone, sigs[0], t); err != nil {
		return nil, err
	}
	trusted := roots(sigs[0], t)
	if len(trusted) == 0 {
		return nil, ErrSignature
	}
	clock := dsig.NewRealClock()
	if t.Now != nil {
		clock = dsig.NewClock(t.Now)
	}
	// Without KeyInfo, goxmldsig needs exactly one candidate root; try each.
	candidates := [][]*x509.Certificate{trusted}
	if len(directChildren(sigs[0], NSDSig, "KeyInfo")) == 0 && len(trusted) > 1 {
		candidates = nil
		for _, c := range trusted {
			candidates = append(candidates, []*x509.Certificate{c})
		}
	}
	for _, set := range candidates {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: set})
		ctx.IdAttribute = "ID"
		ctx.Clock = clock
		ctx.IgnoreCertificateValidity = true
		verified, err := ctx.Validate(standalone)
		if err != nil {
			continue
		}
		canonical, err := Canonicalize(verified, false)
		if err != nil {
			return nil, ErrSignature
		}
		doc, err := Parse(canonical)
		if err != nil {
			return nil, ErrSignature
		}
		return doc.Root(), nil
	}
	return nil, ErrSignature
}

// VerifiedResponse is a SAML Response whose assertion is covered by a trusted
// signature. Assertion is always a verified element; Response is the verified
// response when ResponseSigned, else the unverified one (envelope fields only).
type VerifiedResponse struct {
	Response        *etree.Element
	Assertion       *etree.Element
	ResponseSigned  bool
	AssertionSigned bool
}

// DecryptFunc opens an EncryptedAssertion into its Assertion element.
type DecryptFunc func(encrypted *etree.Element) (*etree.Element, error)

// checkMessageShape refuses wrapping shapes before any signature work: the
// root must be a Response with exactly one (Encrypted)Assertion in the whole
// document, as its direct child; IDs are unique; signatures sit only on the
// Response or the Assertion.
func checkMessageShape(root *etree.Element) error {
	if !inNS(root, NSProtocol, "Response") {
		return ErrStructure
	}
	all := append(descendants(root, NSAssertion, "Assertion"), descendants(root, NSAssertion, "EncryptedAssertion")...)
	direct := append(directChildren(root, NSAssertion, "Assertion"), directChildren(root, NSAssertion, "EncryptedAssertion")...)
	if len(all) != 1 || len(direct) != 1 {
		return ErrStructure
	}
	if err := uniqueIDs(root); err != nil {
		return err
	}
	for _, sig := range descendants(root, NSDSig, "Signature") {
		if p := sig.Parent(); p != root && p != direct[0] {
			return ErrStructure
		}
	}
	return nil
}

func uniqueIDs(root *etree.Element) error {
	seen := map[string]bool{}
	var walk func(*etree.Element) error
	walk = func(e *etree.Element) error {
		if id := e.SelectAttrValue("ID", ""); id != "" {
			if seen[id] {
				return ErrStructure
			}
			seen[id] = true
		}
		for _, c := range e.ChildElements() {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root)
}

// VerifyResponse verifies a SAML Response: the response signature when
// present, then (after decrypting an EncryptedAssertion) the assertion
// signature when present. At least one must cover the assertion. The
// assertion returned is read from verified bytes only.
func VerifyResponse(doc *etree.Document, t Trust, decrypt DecryptFunc) (*VerifiedResponse, error) {
	if doc == nil || doc.Root() == nil {
		return nil, ErrStructure
	}
	root := doc.Root()
	if err := checkMessageShape(root); err != nil {
		return nil, err
	}
	out := &VerifiedResponse{Response: root}
	if len(directChildren(root, NSDSig, "Signature")) > 0 {
		verified, err := VerifyEnveloped(root, t)
		if err != nil {
			return nil, err
		}
		out.Response, out.ResponseSigned = verified, true
	}
	assertion := directChildren(out.Response, NSAssertion, "Assertion")
	if len(assertion) == 0 {
		enc := directChildren(out.Response, NSAssertion, "EncryptedAssertion")
		if len(enc) != 1 || decrypt == nil {
			return nil, ErrStructure
		}
		opened, err := decrypt(enc[0])
		if err != nil {
			return nil, err
		}
		if !inNS(opened, NSAssertion, "Assertion") || len(descendants(opened, NSAssertion, "Assertion")) != 0 || uniqueIDs(opened) != nil {
			return nil, ErrStructure
		}
		for _, sig := range descendants(opened, NSDSig, "Signature") {
			if sig.Parent() != opened {
				return nil, ErrStructure
			}
		}
		assertion = []*etree.Element{opened}
	}
	if len(assertion) != 1 {
		return nil, ErrStructure
	}
	a := assertion[0]
	if len(directChildren(a, NSDSig, "Signature")) > 0 {
		verified, err := VerifyEnveloped(a, t)
		if err != nil {
			return nil, err
		}
		a, out.AssertionSigned = verified, true
	} else if !out.ResponseSigned {
		return nil, ErrUnsigned
	}
	if !out.AssertionSigned {
		// Read the assertion through the same canonical re-parse.
		detached, err := detach(a)
		if err != nil {
			return nil, err
		}
		canonical, err := Canonicalize(detached, false)
		if err != nil {
			return nil, ErrStructure
		}
		parsed, err := Parse(canonical)
		if err != nil {
			return nil, ErrStructure
		}
		a = parsed.Root()
	}
	out.Assertion = a
	return out, nil
}

// NameID returns the assertion subject's NameID value.
func NameID(assertion *etree.Element) string {
	if assertion == nil {
		return ""
	}
	subj := directChildren(assertion, NSAssertion, "Subject")
	if len(subj) != 1 {
		return ""
	}
	ids := directChildren(subj[0], NSAssertion, "NameID")
	if len(ids) != 1 {
		return ""
	}
	return ids[0].Text()
}
