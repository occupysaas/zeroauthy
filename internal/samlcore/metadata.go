package samlcore

import (
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// Endpoint is a metadata service endpoint.
type Endpoint struct {
	Binding, Location, ResponseLocation string
}

// IdPDescriptor is an IDPSSODescriptor.
type IdPDescriptor struct {
	SigningCerts            []*x509.Certificate
	SSO, SLO                []Endpoint
	NameIDFormats           []string
	WantAuthnRequestsSigned bool
}

// SPDescriptor is an SPSSODescriptor.
type SPDescriptor struct {
	SigningCerts, EncryptionCerts             []*x509.Certificate
	ACS, SLO                                  []Endpoint
	NameIDFormats                             []string
	AuthnRequestsSigned, WantAssertionsSigned bool
}

// EntityDescriptor is one SAML metadata entity.
type EntityDescriptor struct {
	EntityID string
	IdP      *IdPDescriptor
	SP       *SPDescriptor
}

func location(eps []Endpoint, binding string) string {
	for _, e := range eps {
		if e.Binding == binding {
			return e.Location
		}
	}
	return ""
}

// SSOLocation returns the single sign-on URL for a binding, or "".
func (d *IdPDescriptor) SSOLocation(binding string) string { return location(d.SSO, binding) }

// SLOLocation returns the single logout URL for a binding, or "".
func (d *IdPDescriptor) SLOLocation(binding string) string { return location(d.SLO, binding) }

func addKeys(parent *etree.Element, use string, certs []*x509.Certificate) {
	for _, c := range certs {
		kd := parent.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", use)
		ki := kd.CreateElement("ds:KeyInfo")
		ki.CreateAttr("xmlns:ds", NSDSig)
		ki.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(c.Raw))
	}
}

func addEndpoints(parent *etree.Element, tag string, eps []Endpoint, indexed bool) {
	for i, e := range eps {
		el := parent.CreateElement(tag)
		el.CreateAttr("Binding", e.Binding)
		el.CreateAttr("Location", e.Location)
		if e.ResponseLocation != "" {
			el.CreateAttr("ResponseLocation", e.ResponseLocation)
		}
		if indexed {
			el.CreateAttr("index", strconv.Itoa(i))
		}
	}
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// BuildMetadata returns an md:EntityDescriptor.
func BuildMetadata(e EntityDescriptor) *etree.Element {
	ed := etree.NewElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", NSMetadata)
	ed.CreateAttr("entityID", e.EntityID)
	if e.IdP != nil {
		d := ed.CreateElement("md:IDPSSODescriptor")
		d.CreateAttr("protocolSupportEnumeration", NSProtocol)
		if e.IdP.WantAuthnRequestsSigned {
			d.CreateAttr("WantAuthnRequestsSigned", "true")
		}
		addKeys(d, "signing", e.IdP.SigningCerts)
		addEndpoints(d, "md:SingleLogoutService", e.IdP.SLO, false)
		for _, f := range e.IdP.NameIDFormats {
			d.CreateElement("md:NameIDFormat").SetText(f)
		}
		addEndpoints(d, "md:SingleSignOnService", e.IdP.SSO, false)
	}
	if e.SP != nil {
		d := ed.CreateElement("md:SPSSODescriptor")
		d.CreateAttr("protocolSupportEnumeration", NSProtocol)
		d.CreateAttr("AuthnRequestsSigned", boolAttr(e.SP.AuthnRequestsSigned))
		d.CreateAttr("WantAssertionsSigned", boolAttr(e.SP.WantAssertionsSigned))
		addKeys(d, "signing", e.SP.SigningCerts)
		addKeys(d, "encryption", e.SP.EncryptionCerts)
		addEndpoints(d, "md:SingleLogoutService", e.SP.SLO, false)
		for _, f := range e.SP.NameIDFormats {
			d.CreateElement("md:NameIDFormat").SetText(f)
		}
		addEndpoints(d, "md:AssertionConsumerService", e.SP.ACS, true)
	}
	return ed
}

func readKeys(d *etree.Element) (signing, encryption []*x509.Certificate) {
	for _, kd := range directChildren(d, NSMetadata, "KeyDescriptor") {
		use := kd.SelectAttrValue("use", "")
		for _, ki := range directChildren(kd, NSDSig, "KeyInfo") {
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
					if use == "" || use == "signing" {
						signing = append(signing, cert)
					}
					if use == "" || use == "encryption" {
						encryption = append(encryption, cert)
					}
				}
			}
		}
	}
	return signing, encryption
}

func readEndpoints(d *etree.Element, tag string) []Endpoint {
	var out []Endpoint
	for _, e := range directChildren(d, NSMetadata, tag) {
		out = append(out, Endpoint{Binding: e.SelectAttrValue("Binding", ""), Location: e.SelectAttrValue("Location", ""), ResponseLocation: e.SelectAttrValue("ResponseLocation", "")})
	}
	return out
}

func readFormats(d *etree.Element) []string {
	var out []string
	for _, f := range directChildren(d, NSMetadata, "NameIDFormat") {
		out = append(out, strings.TrimSpace(f.Text()))
	}
	return out
}

// ParseMetadata reads an EntityDescriptor, or an EntitiesDescriptor holding
// exactly one entity.
func ParseMetadata(raw []byte) (*EntityDescriptor, error) {
	doc, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	root := doc.Root()
	if inNS(root, NSMetadata, "EntitiesDescriptor") {
		entities := directChildren(root, NSMetadata, "EntityDescriptor")
		if len(entities) != 1 {
			return nil, errorf("metadata must describe exactly one entity")
		}
		root = entities[0]
	}
	if !inNS(root, NSMetadata, "EntityDescriptor") || root.SelectAttrValue("entityID", "") == "" {
		return nil, ErrStructure
	}
	out := &EntityDescriptor{EntityID: root.SelectAttrValue("entityID", "")}
	if d := directChildren(root, NSMetadata, "IDPSSODescriptor"); len(d) > 0 {
		signing, _ := readKeys(d[0])
		out.IdP = &IdPDescriptor{SigningCerts: signing, SSO: readEndpoints(d[0], "SingleSignOnService"), SLO: readEndpoints(d[0], "SingleLogoutService"),
			NameIDFormats: readFormats(d[0]), WantAuthnRequestsSigned: d[0].SelectAttrValue("WantAuthnRequestsSigned", "") == "true"}
	}
	if d := directChildren(root, NSMetadata, "SPSSODescriptor"); len(d) > 0 {
		signing, encryption := readKeys(d[0])
		out.SP = &SPDescriptor{SigningCerts: signing, EncryptionCerts: encryption, ACS: readEndpoints(d[0], "AssertionConsumerService"),
			SLO: readEndpoints(d[0], "SingleLogoutService"), NameIDFormats: readFormats(d[0]),
			AuthnRequestsSigned: d[0].SelectAttrValue("AuthnRequestsSigned", "") == "true", WantAssertionsSigned: d[0].SelectAttrValue("WantAssertionsSigned", "") == "true"}
	}
	if out.IdP == nil && out.SP == nil {
		return nil, ErrStructure
	}
	return out, nil
}
