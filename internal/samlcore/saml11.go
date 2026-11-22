package samlcore

import (
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// SAML 1.1 and WS-Trust names used by WS-Federation (Plan 37b, D-0140).
const (
	NSAssertion11 = "urn:oasis:names:tc:SAML:1.0:assertion"
	// NSTrust2005 is the WS-Trust namespace node-wsfed's
	// RequestSecurityTokenResponse uses; NSTrust13 is WS-Trust 1.3, which
	// ADFS may send (as a RequestSecurityTokenResponseCollection).
	NSTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	NSTrust13   = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"

	ConfirmBearer11      = "urn:oasis:names:tc:SAML:1.0:cm:bearer"
	AuthMethodPassword11 = "urn:oasis:names:tc:SAML:1.0:am:password"
	TokenTypeSAML11      = "urn:oasis:names:tc:SAML:1.0:assertion"
	TokenTypeSAML20      = "urn:oasis:names:tc:SAML:2.0:assertion"

	idAttr11 = "AssertionID"
)

// Assertion11Spec is what the WS-Fed identity provider puts in a SAML 1.1
// assertion (node-saml's saml11 template, D-0140).
type Assertion11Spec struct {
	ID, Issuer, NameID, NameIDFormat, Audience          string
	IssueInstant, NotBefore, NotOnOrAfter, AuthnInstant time.Time
	Attributes                                          []Attribute
}

// splitClaim splits a claim type at its last "/" into the SAML 1.1
// AttributeNamespace and AttributeName (node-saml).
func splitClaim(name string) (string, string) {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

func subject11(parent *etree.Element, s Assertion11Spec) {
	subj := parent.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameIdentifier")
	format := s.NameIDFormat
	if format == "" {
		format = NameIDUnspecified
	}
	nid.CreateAttr("Format", format)
	nid.SetText(s.NameID)
	subj.CreateElement("saml:SubjectConfirmation").CreateElement("saml:ConfirmationMethod").SetText(ConfirmBearer11)
}

// BuildAssertion11 returns a standalone SAML 1.1 saml:Assertion ready to
// sign with SignEnveloped11.
func BuildAssertion11(s Assertion11Spec) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", NSAssertion11)
	a.CreateAttr("MajorVersion", "1")
	a.CreateAttr("MinorVersion", "1")
	a.CreateAttr(idAttr11, s.ID)
	a.CreateAttr("Issuer", s.Issuer)
	a.CreateAttr("IssueInstant", FormatTime(s.IssueInstant))
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", FormatTime(s.NotBefore))
	cond.CreateAttr("NotOnOrAfter", FormatTime(s.NotOnOrAfter))
	cond.CreateElement("saml:AudienceRestrictionCondition").CreateElement("saml:Audience").SetText(s.Audience)
	if len(s.Attributes) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		subject11(st, s)
		for _, attr := range s.Attributes {
			ns, name := splitClaim(attr.Name)
			ae := st.CreateElement("saml:Attribute")
			ae.CreateAttr("AttributeNamespace", ns)
			ae.CreateAttr("AttributeName", name)
			for _, v := range attr.Values {
				ae.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	st := a.CreateElement("saml:AuthenticationStatement")
	st.CreateAttr("AuthenticationMethod", AuthMethodPassword11)
	st.CreateAttr("AuthenticationInstant", FormatTime(s.AuthnInstant))
	subject11(st, s)
	return a
}

// SignEnveloped11 returns a signed copy of a SAML 1.1 assertion: the
// reference names its AssertionID and the Signature is its last child, as
// the SAML 1.1 schema requires.
func (s Signer) SignEnveloped11(el *etree.Element) (*etree.Element, error) {
	if el == nil || el.SelectAttrValue(idAttr11, "") == "" {
		return nil, errorf("element to sign has no AssertionID")
	}
	ctx, err := s.context()
	if err != nil {
		return nil, err
	}
	ctx.IdAttribute = idAttr11
	signed, err := ctx.SignEnveloped(el.Copy())
	if err != nil {
		return nil, errorf("signing failed")
	}
	return signed, nil
}

// BuildRSTR wraps a signed token in node-wsfed's
// t:RequestSecurityTokenResponse, with Context = wctx when present, and
// serializes it for the wresult form field.
func BuildRSTR(wctx string, token *etree.Element) (string, error) {
	root := etree.NewElement("t:RequestSecurityTokenResponse")
	if wctx != "" {
		root.CreateAttr("Context", wctx)
	}
	root.CreateAttr("xmlns:t", NSTrust2005)
	root.CreateElement("t:RequestedSecurityToken").AddChild(token.Copy())
	doc := etree.NewDocument()
	doc.SetRoot(root)
	out, err := doc.WriteToString()
	if err != nil {
		return "", errorf("serialize RSTR: %v", err)
	}
	return out, nil
}

// WSFedToken is a verified token from a WS-Federation wresult: a SAML 1.1
// or SAML 2.0 assertion. Attribute names are full claim types (SAML 1.1
// AttributeNamespace + "/" + AttributeName).
type WSFedToken struct {
	Version, ID, Issuer, NameID, NameIDFormat           string
	IssueInstant, NotBefore, NotOnOrAfter, AuthnInstant time.Time
	Audiences                                           []string
	AudienceRestrictions                                [][]string
	Bearer                                              bool
	Attributes                                          map[string][]string
	AttributeOrder                                      []string
}

// rstrOf returns the single RequestSecurityTokenResponse of a wresult: the
// root, or the only child of a WS-Trust 1.3 collection.
func rstrOf(root *etree.Element) (*etree.Element, string, error) {
	for _, ns := range []string{NSTrust2005, NSTrust13} {
		if inNS(root, ns, "RequestSecurityTokenResponse") {
			return root, ns, nil
		}
		if inNS(root, ns, "RequestSecurityTokenResponseCollection") {
			kids := root.ChildElements()
			if len(kids) != 1 || !inNS(kids[0], ns, "RequestSecurityTokenResponse") {
				return nil, "", ErrStructure
			}
			return kids[0], ns, nil
		}
	}
	return nil, "", ErrStructure
}

func uniqueIDs11(root *etree.Element) error {
	seen := map[string]bool{}
	var walk func(*etree.Element) error
	walk = func(e *etree.Element) error {
		for _, name := range []string{"ID", idAttr11} {
			if id := e.SelectAttrValue(name, ""); id != "" {
				if seen[id] {
					return ErrStructure
				}
				seen[id] = true
			}
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

// VerifyWSFedToken parses a wresult and verifies its token. The shape is
// refused before any signature work unless the document holds exactly one
// assertion (SAML 1.1 or 2.0), as the only child of the only
// RequestedSecurityToken, with signatures only directly on it; the
// assertion's own enveloped signature must be trusted. Values are read
// from the verified canonical form only.
func VerifyWSFedToken(raw []byte, t Trust) (*WSFedToken, error) {
	doc, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	rstr, ns, err := rstrOf(doc.Root())
	if err != nil {
		return nil, err
	}
	tokens := directChildren(rstr, ns, "RequestedSecurityToken")
	if len(tokens) != 1 || len(tokens[0].ChildElements()) != 1 {
		return nil, ErrStructure
	}
	a := tokens[0].ChildElements()[0]
	root := doc.Root()
	all := slices.Concat(descendants(root, NSAssertion11, "Assertion"), descendants(root, NSAssertion, "Assertion"),
		descendants(root, NSAssertion, "EncryptedAssertion"))
	if len(all) != 1 || all[0] != a {
		return nil, ErrStructure
	}
	if err := uniqueIDs11(root); err != nil {
		return nil, err
	}
	for _, sig := range descendants(root, NSDSig, "Signature") {
		if sig.Parent() != a {
			return nil, ErrStructure
		}
	}
	if len(directChildren(a, NSDSig, "Signature")) == 0 {
		return nil, ErrUnsigned
	}
	switch {
	case inNS(a, NSAssertion11, "Assertion"):
		verified, err := verifyEnveloped(a, t, idAttr11)
		if err != nil {
			return nil, err
		}
		return parseAssertion11(verified)
	case inNS(a, NSAssertion, "Assertion"):
		verified, err := VerifyEnveloped(a, t)
		if err != nil {
			return nil, err
		}
		p, err := ParseAssertion(verified)
		if err != nil {
			return nil, err
		}
		return &WSFedToken{Version: "2.0", ID: p.ID, Issuer: p.Issuer, NameID: p.NameID, NameIDFormat: p.NameIDFormat,
			IssueInstant: p.IssueInstant, NotBefore: p.NotBefore, NotOnOrAfter: p.NotOnOrAfter, AuthnInstant: p.AuthnInstant,
			Audiences: p.Audiences, AudienceRestrictions: p.AudienceRestrictions, Bearer: p.Bearer, Attributes: p.Attributes,
			AttributeOrder: p.AttributeOrder}, nil
	}
	return nil, ErrStructure
}

// subjectOf11 reads a SAML 1.1 statement's Subject.
func subjectOf11(st *etree.Element) (nameID, format string, bearer, ok bool) {
	subj := directChildren(st, NSAssertion11, "Subject")
	if len(subj) != 1 {
		return "", "", false, false
	}
	if nid := directChildren(subj[0], NSAssertion11, "NameIdentifier"); len(nid) == 1 {
		nameID, format = strings.TrimSpace(nid[0].Text()), nid[0].SelectAttrValue("Format", "")
	}
	for _, sc := range directChildren(subj[0], NSAssertion11, "SubjectConfirmation") {
		for _, cm := range directChildren(sc, NSAssertion11, "ConfirmationMethod") {
			bearer = bearer || strings.TrimSpace(cm.Text()) == ConfirmBearer11
		}
	}
	return nameID, format, bearer, true
}

func parseAssertion11(el *etree.Element) (*WSFedToken, error) {
	if el.SelectAttrValue("MajorVersion", "") != "1" || el.SelectAttrValue(idAttr11, "") == "" {
		return nil, ErrStructure
	}
	tok := &WSFedToken{Version: "1.1", ID: el.SelectAttrValue(idAttr11, ""), Issuer: el.SelectAttrValue("Issuer", ""), Attributes: map[string][]string{}}
	tok.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	if cond := directChildren(el, NSAssertion11, "Conditions"); len(cond) == 1 {
		tok.NotBefore, _ = parseTime(cond[0].SelectAttrValue("NotBefore", ""))
		tok.NotOnOrAfter, _ = parseTime(cond[0].SelectAttrValue("NotOnOrAfter", ""))
		for _, ar := range directChildren(cond[0], NSAssertion11, "AudienceRestrictionCondition") {
			var set []string
			for _, au := range directChildren(ar, NSAssertion11, "Audience") {
				set = append(set, strings.TrimSpace(au.Text()))
			}
			tok.Audiences = append(tok.Audiences, set...)
			tok.AudienceRestrictions = append(tok.AudienceRestrictions, set)
		}
	} else if len(cond) > 1 {
		return nil, ErrStructure
	}
	// Every statement subject must name the same principal.
	statements := slices.Concat(directChildren(el, NSAssertion11, "AuthenticationStatement"), directChildren(el, NSAssertion11, "AttributeStatement"))
	for i, st := range statements {
		nameID, format, bearer, ok := subjectOf11(st)
		if !ok {
			return nil, ErrStructure
		}
		if i == 0 {
			tok.NameID, tok.NameIDFormat, tok.Bearer = nameID, format, bearer
		} else if nameID != tok.NameID {
			return nil, ErrStructure
		} else {
			tok.Bearer = tok.Bearer && bearer
		}
	}
	for _, st := range directChildren(el, NSAssertion11, "AuthenticationStatement") {
		tok.AuthnInstant, _ = parseTime(st.SelectAttrValue("AuthenticationInstant", ""))
	}
	for _, st := range directChildren(el, NSAssertion11, "AttributeStatement") {
		for _, attr := range directChildren(st, NSAssertion11, "Attribute") {
			ns, name := attr.SelectAttrValue("AttributeNamespace", ""), attr.SelectAttrValue("AttributeName", "")
			if name == "" {
				continue
			}
			full := name
			if ns != "" {
				full = strings.TrimSuffix(ns, "/") + "/" + name
			}
			if _, seen := tok.Attributes[full]; !seen {
				tok.AttributeOrder = append(tok.AttributeOrder, full)
			}
			for _, v := range directChildren(attr, NSAssertion11, "AttributeValue") {
				tok.Attributes[full] = append(tok.Attributes[full], v.Text())
			}
		}
	}
	return tok, nil
}

// WSFedExpect is what a WS-Fed relying party requires of a token.
type WSFedExpect struct {
	Now      time.Time
	Skew     time.Duration
	Audience string
}

// Check validates the bearer confirmation, validity window and audience:
// every audience restriction must name the audience and there must be one.
func (tok *WSFedToken) Check(e WSFedExpect) error {
	refuse := errorf("token conditions not met")
	if !tok.Bearer || tok.NotOnOrAfter.IsZero() {
		return refuse
	}
	if !tok.NotBefore.IsZero() && e.Now.Add(e.Skew).Before(tok.NotBefore) {
		return refuse
	}
	if !e.Now.Add(-e.Skew).Before(tok.NotOnOrAfter) {
		return refuse
	}
	ok := len(tok.AudienceRestrictions) > 0
	for _, set := range tok.AudienceRestrictions {
		ok = ok && slices.Contains(set, e.Audience)
	}
	if !ok {
		return refuse
	}
	return nil
}
