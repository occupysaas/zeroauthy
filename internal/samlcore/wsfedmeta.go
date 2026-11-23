package samlcore

import (
	"crypto/x509"
	"encoding/base64"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// WS-Federation metadata names (node-wsfed's template, D-0140).
const (
	NSWSFed      = "http://docs.oasis-open.org/wsfed/federation/200706"
	NSWSFedAuth  = "http://docs.oasis-open.org/wsfed/authorization/200706"
	NSAddressing = "http://www.w3.org/2005/08/addressing"
)

// wsfedClaimTypes are the claim types node-wsfed offers, all optional.
var wsfedClaimTypes = []struct{ uri, name, description string }{
	{ClaimEmail, "E-Mail Address", "The e-mail address of the user"},
	{ClaimGivenName, "Given Name", "The given name of the user"},
	{ClaimName, "Name", "The unique name of the user"},
	{ClaimSurname, "Surname", "The surname of the user"},
	{ClaimNameIdentifier, "Name ID", "The SAML name identifier of the user"},
}

// BuildWSFedMetadata returns the federation metadata of a WS-Fed identity
// provider: a SecurityTokenServiceType role with the signing certificates,
// the offered token and claim types and the passive requestor endpoint.
func BuildWSFedMetadata(entityID, endpoint string, certs []*x509.Certificate) *etree.Element {
	ed := etree.NewElement("EntityDescriptor")
	ed.CreateAttr("xmlns", NSMetadata)
	ed.CreateAttr("entityID", entityID)
	role := ed.CreateElement("RoleDescriptor")
	role.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	role.CreateAttr("xmlns:fed", NSWSFed)
	role.CreateAttr("xsi:type", "fed:SecurityTokenServiceType")
	role.CreateAttr("protocolSupportEnumeration", NSWSFed)
	role.CreateAttr("ServiceDisplayName", entityID)
	for _, c := range certs {
		kd := role.CreateElement("KeyDescriptor")
		kd.CreateAttr("use", "signing")
		ki := kd.CreateElement("KeyInfo")
		ki.CreateAttr("xmlns", NSDSig)
		ki.CreateElement("X509Data").CreateElement("X509Certificate").SetText(base64.StdEncoding.EncodeToString(c.Raw))
	}
	tt := role.CreateElement("fed:TokenTypesOffered")
	for _, uri := range []string{TokenTypeSAML20, TokenTypeSAML11} {
		tt.CreateElement("fed:TokenType").CreateAttr("Uri", uri)
	}
	ct := role.CreateElement("fed:ClaimTypesOffered")
	for _, c := range wsfedClaimTypes {
		el := ct.CreateElement("auth:ClaimType")
		el.CreateAttr("xmlns:auth", NSWSFedAuth)
		el.CreateAttr("Uri", c.uri)
		el.CreateAttr("Optional", "true")
		el.CreateElement("auth:DisplayName").SetText(c.name)
		el.CreateElement("auth:Description").SetText(c.description)
	}
	ref := role.CreateElement("fed:PassiveRequestorEndpoint").CreateElement("EndpointReference")
	ref.CreateAttr("xmlns", NSAddressing)
	ref.CreateElement("Address").SetText(endpoint)
	return ed
}

// WSFedMetadata is a WS-Fed identity provider's federation metadata.
type WSFedMetadata struct {
	EntityID        string
	PassiveEndpoint string
	SigningCerts    []*x509.Certificate
}

// isSTSRole reports whether a RoleDescriptor is a WS-Fed
// SecurityTokenServiceType: its xsi:type QName resolves to the federation
// namespace.
func isSTSRole(el *etree.Element) bool {
	t := el.SelectAttrValue("xsi:type", "")
	prefix, local, ok := strings.Cut(t, ":")
	if !ok {
		prefix, local = "", t
	}
	if local != "SecurityTokenServiceType" {
		return false
	}
	ns := ""
	for e := el; e != nil && ns == ""; e = e.Parent() {
		for _, a := range e.Attr {
			if prefix != "" && a.Space == "xmlns" && a.Key == prefix || prefix == "" && a.Space == "" && a.Key == "xmlns" {
				ns = a.Value
				break
			}
		}
	}
	return ns == NSWSFed
}

// ParseWSFedMetadata reads federation metadata (an EntityDescriptor, or an
// EntitiesDescriptor holding one) for its SecurityTokenServiceType role:
// signing certificates and the passive requestor endpoint. The metadata's
// own signature is not checked: it is configured by the tenant or fetched
// over HTTPS from the configured server.
func ParseWSFedMetadata(raw []byte) (*WSFedMetadata, error) {
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
	out := &WSFedMetadata{EntityID: root.SelectAttrValue("entityID", "")}
	for _, role := range directChildren(root, NSMetadata, "RoleDescriptor") {
		if !isSTSRole(role) {
			continue
		}
		signing, _ := readKeys(role)
		out.SigningCerts = append(out.SigningCerts, signing...)
		for _, ep := range directChildren(role, NSWSFed, "PassiveRequestorEndpoint") {
			for _, ref := range directChildren(ep, NSAddressing, "EndpointReference") {
				for _, addr := range directChildren(ref, NSAddressing, "Address") {
					if out.PassiveEndpoint == "" {
						out.PassiveEndpoint = strings.TrimSpace(addr.Text())
					}
				}
			}
		}
	}
	if out.PassiveEndpoint == "" || len(out.SigningCerts) == 0 {
		return nil, errorf("metadata has no WS-Federation security token service with a signing certificate")
	}
	return out, nil
}
