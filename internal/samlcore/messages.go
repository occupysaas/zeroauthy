package samlcore

import (
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// Bindings, name ID formats, status codes and claim types.
const (
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	AuthnContextUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusAuthnFail = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	AttrNameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	confirmBearer     = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

	ClaimNameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
	ClaimEmail          = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	ClaimName           = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	ClaimGivenName      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
	ClaimSurname        = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
	ClaimUPN            = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	ClaimGroups         = "http://schemas.xmlsoap.org/claims/Group"
)

// FormatTime is the SAML xs:dateTime form zeroauthy writes (UTC, millis).
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// DefaultRequestTemplate is Auth0's documented AuthnRequest template.
const DefaultRequestTemplate = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" @@AssertServiceURLAndDestination@@ ID="@@ID@@" IssueInstant="@@IssueInstant@@" ProtocolBinding="@@ProtocolBinding@@" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer></samlp:AuthnRequest>`

// AuthnRequest is the part of a SAML AuthnRequest zeroauthy builds or reads.
type AuthnRequest struct {
	ID, Issuer, Destination, ACSURL, ProtocolBinding, NameIDFormat string
	IssueInstant                                                   time.Time
	ForceAuthn, IsPassive                                          bool
	AuthnContextClassRefs                                          []string
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func substitute(template string, r AuthnRequest) string {
	esc := xmlEscape
	return strings.NewReplacer(
		"@@AssertServiceURLAndDestination@@", `AssertionConsumerServiceURL="`+esc(r.ACSURL)+`" Destination="`+esc(r.Destination)+`"`,
		"@@AssertionConsumerServiceURL@@", esc(r.ACSURL),
		"@@Destination@@", esc(r.Destination),
		"@@ID@@", esc(r.ID),
		"@@IssueInstant@@", FormatTime(r.IssueInstant),
		"@@ProtocolBinding@@", esc(r.ProtocolBinding),
		"@@Issuer@@", esc(r.Issuer),
	).Replace(template)
}

// ValidateRequestTemplate checks that a requestTemplate produces a parseable
// AuthnRequest whose ID comes from @@ID@@.
func ValidateRequestTemplate(template string) error {
	if !strings.Contains(template, "@@ID@@") {
		return errorf("requestTemplate must use @@ID@@")
	}
	el, err := BuildAuthnRequest(AuthnRequest{ID: "_template_check", IssueInstant: time.Unix(0, 0), Issuer: "urn:check", Destination: "https://idp.invalid/", ACSURL: "https://sp.invalid/", ProtocolBinding: BindingPOST}, template)
	if err != nil {
		return err
	}
	if el.SelectAttrValue("ID", "") != "_template_check" {
		return errorf("requestTemplate must use @@ID@@ as the ID")
	}
	return nil
}

// BuildAuthnRequest fills template ("" = DefaultRequestTemplate) with
// XML-escaped values; the result must be a samlp:AuthnRequest.
func BuildAuthnRequest(r AuthnRequest, template string) (*etree.Element, error) {
	if template == "" {
		template = DefaultRequestTemplate
	}
	doc, err := Parse([]byte(substitute(template, r)))
	if err != nil {
		return nil, errorf("requestTemplate does not produce valid XML")
	}
	root := doc.Root()
	if !inNS(root, NSProtocol, "AuthnRequest") {
		return nil, errorf("requestTemplate does not produce an AuthnRequest")
	}
	return root, nil
}

func childText(el *etree.Element, ns, tag string) string {
	if el == nil {
		return ""
	}
	c := directChildren(el, ns, tag)
	if len(c) != 1 {
		return ""
	}
	return strings.TrimSpace(c[0].Text())
}

// ParseAuthnRequest reads an AuthnRequest.
func ParseAuthnRequest(el *etree.Element) (*AuthnRequest, error) {
	if el == nil || !inNS(el, NSProtocol, "AuthnRequest") || el.SelectAttrValue("ID", "") == "" {
		return nil, ErrStructure
	}
	r := &AuthnRequest{ID: el.SelectAttrValue("ID", ""), Destination: el.SelectAttrValue("Destination", ""),
		ACSURL: el.SelectAttrValue("AssertionConsumerServiceURL", ""), ProtocolBinding: el.SelectAttrValue("ProtocolBinding", ""),
		ForceAuthn: el.SelectAttrValue("ForceAuthn", "") == "true", IsPassive: el.SelectAttrValue("IsPassive", "") == "true",
		Issuer: childText(el, NSAssertion, "Issuer")}
	r.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	if p := directChildren(el, NSProtocol, "NameIDPolicy"); len(p) == 1 {
		r.NameIDFormat = p[0].SelectAttrValue("Format", "")
	}
	for _, rac := range directChildren(el, NSProtocol, "RequestedAuthnContext") {
		for _, c := range directChildren(rac, NSAssertion, "AuthnContextClassRef") {
			r.AuthnContextClassRefs = append(r.AuthnContextClassRefs, strings.TrimSpace(c.Text()))
		}
	}
	return r, nil
}

// Attribute is one SAML attribute.
type Attribute struct {
	Name   string
	Values []string
}

// AssertionSpec is what the identity provider puts in an assertion.
type AssertionSpec struct {
	ID, Issuer, NameID, NameIDFormat, Audience, Recipient, InResponseTo, SessionIndex, AuthnContextClassRef string
	IssueInstant, NotBefore, NotOnOrAfter, AuthnInstant                                                     time.Time
	Attributes                                                                                              []Attribute
	TypedAttributes, IncludeNameFormat                                                                      bool
}

// BuildAssertion returns a standalone saml:Assertion ready to sign.
func BuildAssertion(s AssertionSpec) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", NSAssertion)
	if s.TypedAttributes {
		a.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
		a.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	}
	a.CreateAttr("ID", s.ID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", FormatTime(s.IssueInstant))
	a.CreateElement("saml:Issuer").SetText(s.Issuer)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	if s.NameIDFormat != "" {
		nid.CreateAttr("Format", s.NameIDFormat)
	}
	nid.SetText(s.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	if s.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", s.InResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", FormatTime(s.NotOnOrAfter))
	scd.CreateAttr("Recipient", s.Recipient)
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", FormatTime(s.NotBefore))
	cond.CreateAttr("NotOnOrAfter", FormatTime(s.NotOnOrAfter))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(s.Audience)
	if len(s.Attributes) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		for _, attr := range s.Attributes {
			ae := st.CreateElement("saml:Attribute")
			ae.CreateAttr("Name", attr.Name)
			if s.IncludeNameFormat {
				ae.CreateAttr("NameFormat", AttrNameFormatURI)
			}
			for _, v := range attr.Values {
				ve := ae.CreateElement("saml:AttributeValue")
				if s.TypedAttributes {
					ve.CreateAttr("xsi:type", "xs:string")
				}
				ve.SetText(v)
			}
		}
	}
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", FormatTime(s.AuthnInstant))
	if s.SessionIndex != "" {
		as.CreateAttr("SessionIndex", s.SessionIndex)
	}
	ref := s.AuthnContextClassRef
	if ref == "" {
		ref = AuthnContextUnspecified
	}
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(ref)
	return a
}

// ResponseSpec is the Response envelope.
type ResponseSpec struct {
	ID, InResponseTo, Destination, Issuer, StatusCode, StatusMessage string
	IssueInstant                                                     time.Time
}

// BuildResponse returns a standalone samlp:Response around assertion (which
// may be a signed Assertion or an EncryptedAssertion, or nil for an error).
func BuildResponse(s ResponseSpec, assertion *etree.Element) *etree.Element {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", NSProtocol)
	r.CreateAttr("xmlns:saml", NSAssertion)
	r.CreateAttr("ID", s.ID)
	if s.InResponseTo != "" {
		r.CreateAttr("InResponseTo", s.InResponseTo)
	}
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", FormatTime(s.IssueInstant))
	if s.Destination != "" {
		r.CreateAttr("Destination", s.Destination)
	}
	r.CreateElement("saml:Issuer").SetText(s.Issuer)
	st := r.CreateElement("samlp:Status")
	code := s.StatusCode
	if code == "" {
		code = StatusSuccess
	}
	st.CreateElement("samlp:StatusCode").CreateAttr("Value", code)
	if s.StatusMessage != "" {
		st.CreateElement("samlp:StatusMessage").SetText(s.StatusMessage)
	}
	if assertion != nil {
		r.AddChild(assertion.Copy())
	}
	return r
}

// ResponseEnvelope is the Response's own fields.
type ResponseEnvelope struct {
	ID, InResponseTo, Destination, Issuer, StatusCode, StatusMessage string
	IssueInstant                                                     time.Time
}

// ParseResponseEnvelope reads a Response's envelope (status, issuer, IDs).
func ParseResponseEnvelope(el *etree.Element) (*ResponseEnvelope, error) {
	if el == nil || !inNS(el, NSProtocol, "Response") {
		return nil, ErrStructure
	}
	e := &ResponseEnvelope{ID: el.SelectAttrValue("ID", ""), InResponseTo: el.SelectAttrValue("InResponseTo", ""),
		Destination: el.SelectAttrValue("Destination", ""), Issuer: childText(el, NSAssertion, "Issuer")}
	e.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	if st := directChildren(el, NSProtocol, "Status"); len(st) == 1 {
		if c := directChildren(st[0], NSProtocol, "StatusCode"); len(c) == 1 {
			e.StatusCode = c[0].SelectAttrValue("Value", "")
		}
		e.StatusMessage = childText(st[0], NSProtocol, "StatusMessage")
	}
	return e, nil
}

// Assertion is a parsed, verified assertion.
type Assertion struct {
	ID, Issuer, NameID, NameIDFormat, SessionIndex, AuthnContextClassRef string
	IssueInstant, NotBefore, NotOnOrAfter, AuthnInstant                  time.Time
	Audiences                                                            []string
	Bearer                                                               bool
	Recipient, InResponseTo                                              string
	ConfirmationNotOnOrAfter                                             time.Time
	Attributes                                                           map[string][]string
	AttributeOrder                                                       []string
}

// ParseAssertion reads a verified saml:Assertion.
func ParseAssertion(el *etree.Element) (*Assertion, error) {
	if el == nil || !inNS(el, NSAssertion, "Assertion") || el.SelectAttrValue("ID", "") == "" {
		return nil, ErrStructure
	}
	a := &Assertion{ID: el.SelectAttrValue("ID", ""), Issuer: childText(el, NSAssertion, "Issuer"), Attributes: map[string][]string{}}
	a.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	if subj := directChildren(el, NSAssertion, "Subject"); len(subj) == 1 {
		if nid := directChildren(subj[0], NSAssertion, "NameID"); len(nid) == 1 {
			a.NameID, a.NameIDFormat = nid[0].Text(), nid[0].SelectAttrValue("Format", "")
		}
		for _, sc := range directChildren(subj[0], NSAssertion, "SubjectConfirmation") {
			if sc.SelectAttrValue("Method", "") != confirmBearer {
				continue
			}
			a.Bearer = true
			if d := directChildren(sc, NSAssertion, "SubjectConfirmationData"); len(d) == 1 {
				a.Recipient, a.InResponseTo = d[0].SelectAttrValue("Recipient", ""), d[0].SelectAttrValue("InResponseTo", "")
				a.ConfirmationNotOnOrAfter, _ = parseTime(d[0].SelectAttrValue("NotOnOrAfter", ""))
			}
		}
	}
	if cond := directChildren(el, NSAssertion, "Conditions"); len(cond) == 1 {
		a.NotBefore, _ = parseTime(cond[0].SelectAttrValue("NotBefore", ""))
		a.NotOnOrAfter, _ = parseTime(cond[0].SelectAttrValue("NotOnOrAfter", ""))
		for _, ar := range directChildren(cond[0], NSAssertion, "AudienceRestriction") {
			for _, au := range directChildren(ar, NSAssertion, "Audience") {
				a.Audiences = append(a.Audiences, strings.TrimSpace(au.Text()))
			}
		}
	}
	if as := directChildren(el, NSAssertion, "AuthnStatement"); len(as) > 0 {
		a.SessionIndex = as[0].SelectAttrValue("SessionIndex", "")
		a.AuthnInstant, _ = parseTime(as[0].SelectAttrValue("AuthnInstant", ""))
		if ac := directChildren(as[0], NSAssertion, "AuthnContext"); len(ac) == 1 {
			a.AuthnContextClassRef = childText(ac[0], NSAssertion, "AuthnContextClassRef")
		}
	}
	for _, st := range directChildren(el, NSAssertion, "AttributeStatement") {
		for _, attr := range directChildren(st, NSAssertion, "Attribute") {
			name := attr.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			if _, seen := a.Attributes[name]; !seen {
				a.AttributeOrder = append(a.AttributeOrder, name)
			}
			for _, v := range directChildren(attr, NSAssertion, "AttributeValue") {
				a.Attributes[name] = append(a.Attributes[name], v.Text())
			}
		}
	}
	return a, nil
}

// Expect is what the service provider requires of an assertion.
type Expect struct {
	Now                               time.Time
	Skew                              time.Duration
	Audience, Recipient, InResponseTo string
	// AllowUnsolicited accepts an assertion with no InResponseTo when
	// InResponseTo is empty (IdP-initiated login).
	AllowUnsolicited bool
}

// Check validates conditions, audience, bearer confirmation, recipient and
// request correlation.
func (a *Assertion) Check(e Expect) error {
	refuse := errorf("assertion conditions not met")
	if !a.Bearer || a.NotOnOrAfter.IsZero() || a.ConfirmationNotOnOrAfter.IsZero() {
		return refuse
	}
	if !a.NotBefore.IsZero() && e.Now.Add(e.Skew).Before(a.NotBefore) {
		return refuse
	}
	if !e.Now.Add(-e.Skew).Before(a.NotOnOrAfter) || !e.Now.Add(-e.Skew).Before(a.ConfirmationNotOnOrAfter) {
		return refuse
	}
	audienceOK := false
	for _, au := range a.Audiences {
		audienceOK = audienceOK || au == e.Audience
	}
	if !audienceOK || a.Recipient != e.Recipient {
		return refuse
	}
	switch {
	case e.InResponseTo != "":
		if a.InResponseTo != e.InResponseTo {
			return refuse
		}
	case !e.AllowUnsolicited || a.InResponseTo != "":
		return refuse
	}
	return nil
}

// LogoutRequest is a SAML LogoutRequest.
type LogoutRequest struct {
	ID, Issuer, Destination, NameID, NameIDFormat, SessionIndex string
	IssueInstant, NotOnOrAfter                                  time.Time
}

// BuildLogoutRequest returns a standalone samlp:LogoutRequest.
func BuildLogoutRequest(l LogoutRequest) *etree.Element {
	r := etree.NewElement("samlp:LogoutRequest")
	r.CreateAttr("xmlns:samlp", NSProtocol)
	r.CreateAttr("xmlns:saml", NSAssertion)
	r.CreateAttr("ID", l.ID)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", FormatTime(l.IssueInstant))
	if l.Destination != "" {
		r.CreateAttr("Destination", l.Destination)
	}
	if !l.NotOnOrAfter.IsZero() {
		r.CreateAttr("NotOnOrAfter", FormatTime(l.NotOnOrAfter))
	}
	r.CreateElement("saml:Issuer").SetText(l.Issuer)
	nid := r.CreateElement("saml:NameID")
	if l.NameIDFormat != "" {
		nid.CreateAttr("Format", l.NameIDFormat)
	}
	nid.SetText(l.NameID)
	if l.SessionIndex != "" {
		r.CreateElement("samlp:SessionIndex").SetText(l.SessionIndex)
	}
	return r
}

// ParseLogoutRequest reads a LogoutRequest.
func ParseLogoutRequest(el *etree.Element) (*LogoutRequest, error) {
	if el == nil || !inNS(el, NSProtocol, "LogoutRequest") || el.SelectAttrValue("ID", "") == "" {
		return nil, ErrStructure
	}
	l := &LogoutRequest{ID: el.SelectAttrValue("ID", ""), Destination: el.SelectAttrValue("Destination", ""),
		Issuer: childText(el, NSAssertion, "Issuer"), SessionIndex: childText(el, NSProtocol, "SessionIndex")}
	if nid := directChildren(el, NSAssertion, "NameID"); len(nid) == 1 {
		l.NameID, l.NameIDFormat = nid[0].Text(), nid[0].SelectAttrValue("Format", "")
	}
	l.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	l.NotOnOrAfter, _ = parseTime(el.SelectAttrValue("NotOnOrAfter", ""))
	return l, nil
}

// LogoutResponse is a SAML LogoutResponse.
type LogoutResponse struct {
	ID, InResponseTo, Issuer, Destination, StatusCode string
	IssueInstant                                      time.Time
}

// BuildLogoutResponse returns a standalone samlp:LogoutResponse.
func BuildLogoutResponse(l LogoutResponse) *etree.Element {
	r := etree.NewElement("samlp:LogoutResponse")
	r.CreateAttr("xmlns:samlp", NSProtocol)
	r.CreateAttr("xmlns:saml", NSAssertion)
	r.CreateAttr("ID", l.ID)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", FormatTime(l.IssueInstant))
	if l.InResponseTo != "" {
		r.CreateAttr("InResponseTo", l.InResponseTo)
	}
	if l.Destination != "" {
		r.CreateAttr("Destination", l.Destination)
	}
	r.CreateElement("saml:Issuer").SetText(l.Issuer)
	code := l.StatusCode
	if code == "" {
		code = StatusSuccess
	}
	r.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", code)
	return r
}

// ParseLogoutResponse reads a LogoutResponse.
func ParseLogoutResponse(el *etree.Element) (*LogoutResponse, error) {
	if el == nil || !inNS(el, NSProtocol, "LogoutResponse") || el.SelectAttrValue("ID", "") == "" {
		return nil, ErrStructure
	}
	l := &LogoutResponse{ID: el.SelectAttrValue("ID", ""), InResponseTo: el.SelectAttrValue("InResponseTo", ""),
		Destination: el.SelectAttrValue("Destination", ""), Issuer: childText(el, NSAssertion, "Issuer")}
	l.IssueInstant, _ = parseTime(el.SelectAttrValue("IssueInstant", ""))
	if st := directChildren(el, NSProtocol, "Status"); len(st) == 1 {
		if c := directChildren(st[0], NSProtocol, "StatusCode"); len(c) == 1 {
			l.StatusCode = c[0].SelectAttrValue("Value", "")
		}
	}
	return l, nil
}
