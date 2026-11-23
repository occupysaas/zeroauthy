package samlcore

import (
	"crypto/x509"
	"encoding/base64"

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
