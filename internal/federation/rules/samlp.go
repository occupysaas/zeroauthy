package rules

import (
	"crypto/sha1" //nolint:gosec // Auth0's SHA-1 certificate thumbprints are identifiers.
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
)

// SAMLP is the SAML service-provider connection strategy (Plan 37a).
const SAMLP = "samlp"

// SAML bindings accepted for protocolBinding.
const (
	BindingRedirect = samlcore.BindingRedirect
	BindingPOST     = samlcore.BindingPOST
)

// SAMLIdPInitiated is options.idpinitiated.
type SAMLIdPInitiated struct {
	Enabled                            bool
	ClientID, Protocol, AuthorizeQuery string
}

// SAMLSettings are the validated samlp options.
type SAMLSettings struct {
	EntityID, SignInEndpoint, SignOutEndpoint, Destination, Recipient string
	ProtocolBinding, SignatureAlgorithm, DigestAlgorithm              string
	RequestTemplate, UserIDAttribute, MetadataURL, IdPEntityID        string
	Certs                                                             [][]byte // DER
	Thumbprints, Thumbprints384                                       []string
	SignRequest, Deflate, Debug, DisableSignout, AllowRSA15           bool
	FieldsMap                                                         map[string][]string
	IdPInitiated                                                      SAMLIdPInitiated
}

// parseSAMLCert reads a PEM certificate or base64 DER.
func parseSAMLCert(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	der := []byte(nil)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		der = block.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, err
		}
		der = b
		// Base64 of a PEM certificate, Auth0's stored form (the Deploy CLI
		// exports and re-imports it so).
		if block, _ := pem.Decode(b); block != nil && block.Type == "CERTIFICATE" {
			der = block.Bytes
		}
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	return der, nil
}

func samlURL(v any, field string, fail func(string, ...any)) string {
	s, ok := v.(string)
	if !ok || len(s) > maxURLBytes {
		fail("options.%s must be a URL of at most %d bytes", field, maxURLBytes)
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		fail("options.%s must be an absolute http or https URL", field)
		return ""
	}
	return s
}

func samlNames(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, t != "" && len(t) <= 1024
	case []any:
		if len(t) == 0 || len(t) > 16 {
			return nil, false
		}
		var out []string
		for _, e := range t {
			s, ok := e.(string)
			if !ok || s == "" || len(s) > 1024 {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// parseSAML validates samlp options (ConnectionOptionsSAML). Private keys are
// never accepted in options: SP signing and decryption keys come from the
// connection keys API (D-0130).
func parseSAML(in Input) (Settings, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	out := Settings{Strategy: SAMLP, AuthenticationActive: true, ProfileSync: SyncOnEachLogin}
	s := &SAMLSettings{ProtocolBinding: BindingRedirect, Deflate: true, SignatureAlgorithm: "rsa-sha256", DigestAlgorithm: "sha256"}
	out.SAML = s
	if strings.Contains(in.Name, "|") {
		fail("name must not contain |")
	}
	switch in.RootAttributes {
	case "":
	case SyncOnEachLogin, SyncOnFirstLogin, SyncNeverOnLogin:
		out.ProfileSync = in.RootAttributes
	default:
		fail("set_user_root_attributes must be %s, %s or %s", SyncOnEachLogin, SyncOnFirstLogin, SyncNeverOnLogin)
	}
	if v, ok := in.Authentication["active"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			fail("authentication.active must be a boolean")
		}
		out.AuthenticationActive = b
	}
	o := in.Options
	if o == nil {
		o = map[string]any{}
	}
	str := func(k string, max int) string {
		v, ok := o[k]
		if !ok {
			return ""
		}
		x, isStr := v.(string)
		if !isStr || len(x) > max || !cleanText(x) {
			fail("options.%s must be a string of at most %d bytes", k, max)
			return ""
		}
		return x
	}
	// text reads multi-line values (PEM, XML, templates): bounded, no
	// control characters other than whitespace.
	text := func(k string, max int) string {
		v, ok := o[k]
		if !ok {
			return ""
		}
		x, isStr := v.(string)
		if !isStr || len(x) > max || strings.ContainsFunc(x, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' }) {
			fail("options.%s must be a string of at most %d bytes", k, max)
			return ""
		}
		return x
	}
	boolean := func(k string, def bool) bool {
		v, ok := o[k]
		if !ok {
			return def
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", k)
		}
		return b
	}
	for _, k := range []string{"signing_key", "decryptionKey"} {
		if v, ok := o[k].(map[string]any); ok && v["key"] != nil {
			fail("options.%s.key is not accepted; use /api/v2/connections/{id}/keys", k)
		}
	}
	if raw := text("metadataXml", samlcore.MaxInputBytes); raw != "" {
		md, err := samlcore.ParseMetadata([]byte(raw))
		if err != nil || md.IdP == nil {
			fail("options.metadataXml is not identity provider metadata")
		} else {
			s.IdPEntityID = md.EntityID
			s.SignInEndpoint = md.IdP.SSOLocation(BindingRedirect)
			if s.SignInEndpoint == "" {
				s.SignInEndpoint = md.IdP.SSOLocation(BindingPOST)
				s.ProtocolBinding = BindingPOST
			}
			s.SignOutEndpoint = md.IdP.SLOLocation(BindingRedirect)
			for _, c := range md.IdP.SigningCerts {
				s.Certs = append(s.Certs, c.Raw)
			}
		}
	}
	if v, ok := o["metadataUrl"]; ok {
		s.MetadataURL = samlURL(v, "metadataUrl", fail)
	}
	if v, ok := o["signInEndpoint"]; ok {
		s.SignInEndpoint = samlURL(v, "signInEndpoint", fail)
	}
	if v, ok := o["signOutEndpoint"]; ok && v != "" {
		s.SignOutEndpoint = samlURL(v, "signOutEndpoint", fail)
	}
	for _, k := range []string{"destinationUrl", "recipientUrl"} {
		if v, ok := o[k]; ok && v != "" {
			u := samlURL(v, k, fail)
			if k == "destinationUrl" {
				s.Destination = u
			} else {
				s.Recipient = u
			}
		}
	}
	for _, k := range []string{"signingCert", "cert"} {
		if v := text(k, 16384); v != "" {
			der, err := parseSAMLCert(v)
			if err != nil {
				fail("options.%s must be a PEM, base64 PEM or base64 DER certificate", k)
				continue
			}
			if !slices.ContainsFunc(s.Certs, func(c []byte) bool { return string(c) == string(der) }) {
				s.Certs = append(s.Certs, der)
			}
		}
	}
	if s.SignInEndpoint == "" && s.MetadataURL == "" {
		fail("options.signInEndpoint, metadataXml or metadataUrl is required")
	}
	if len(s.Certs) == 0 && s.MetadataURL == "" {
		fail("options.signingCert, metadataXml or metadataUrl is required")
	}
	for _, der := range s.Certs {
		s1 := sha1.Sum(der) //nolint:gosec // thumbprint identifier
		s384 := sha512.Sum384(der)
		s.Thumbprints = append(s.Thumbprints, hex.EncodeToString(s1[:]))
		s.Thumbprints384 = append(s.Thumbprints384, hex.EncodeToString(s384[:]))
	}
	s.EntityID = str("entityId", 1024)
	if b := str("protocolBinding", 1024); b != "" {
		if b != BindingRedirect && b != BindingPOST {
			fail("options.protocolBinding must be the HTTP-Redirect or HTTP-POST binding")
		}
		s.ProtocolBinding = b
	}
	if a := str("signatureAlgorithm", 32); a != "" {
		if a != "rsa-sha256" && a != "rsa-sha1" {
			fail("options.signatureAlgorithm must be rsa-sha256 or rsa-sha1")
		}
		s.SignatureAlgorithm = a
	}
	if a := str("digestAlgorithm", 32); a != "" {
		if a != "sha256" && a != "sha1" {
			fail("options.digestAlgorithm must be sha256 or sha1")
		}
		s.DigestAlgorithm = a
	}
	if t := text("requestTemplate", 16384); t != "" {
		if err := samlcore.ValidateRequestTemplate(t); err != nil {
			fail("options.requestTemplate does not produce a valid AuthnRequest")
		}
		s.RequestTemplate = t
	}
	s.UserIDAttribute = str("user_id_attribute", 1024)
	s.SignRequest = boolean("signSAMLRequest", false)
	s.Deflate = boolean("deflate", true)
	s.Debug = boolean("debug", false)
	s.DisableSignout = boolean("disableSignout", false)
	if v, ok := o["fieldsMap"]; ok {
		m, isObj := v.(map[string]any)
		if !isObj || len(m) > 100 {
			fail("options.fieldsMap must be an object of at most 100 entries")
		} else {
			s.FieldsMap = map[string][]string{}
			for k, names := range m {
				list, valid := samlNames(names)
				if !valid || k == "" || len(k) > 255 {
					fail("options.fieldsMap.%s must be an attribute name or 1 to 16 names", k)
					continue
				}
				s.FieldsMap[k] = list
			}
		}
	}
	if v, ok := o["idpinitiated"]; ok {
		m, isObj := v.(map[string]any)
		if !isObj {
			fail("options.idpinitiated must be an object")
		} else {
			ip := &s.IdPInitiated
			ip.Enabled, _ = m["enabled"].(bool)
			ip.ClientID, _ = m["client_id"].(string)
			ip.Protocol, _ = m["client_protocol"].(string)
			ip.AuthorizeQuery, _ = m["client_authorizequery"].(string)
			if ip.Protocol == "" {
				ip.Protocol = "oidc"
			}
			switch {
			case ip.Protocol != "oidc" && ip.Protocol != "samlp":
				fail("options.idpinitiated.client_protocol must be oidc or samlp (wsfed is not supported)")
			case ip.Enabled && ip.ClientID == "":
				fail("options.idpinitiated.client_id is required when IdP-initiated login is enabled")
			case len(ip.AuthorizeQuery) > maxURLBytes:
				fail("options.idpinitiated.client_authorizequery is too long")
			}
			if _, err := url.ParseQuery(ip.AuthorizeQuery); err != nil {
				fail("options.idpinitiated.client_authorizequery must be a query string")
			}
		}
	}
	if v, ok := o["assertion_decryption_settings"].(map[string]any); ok {
		if list, ok := v["allowed_key_transport"].([]any); ok {
			for _, e := range list {
				switch e {
				case "rsa-oaep", "rsa-oaep-256":
				case "rsa-1_5":
					s.AllowRSA15 = true
				default:
					fail("options.assertion_decryption_settings.allowed_key_transport has an unknown algorithm")
				}
			}
		}
	}
	if v, ok := o["domain_aliases"]; ok {
		aliases, err := ParseDomainAliases(v)
		if err != nil {
			fail("options.domain_aliases: %v", err)
		}
		out.DomainAliases = aliases
	}
	if v, ok := o["icon_url"]; ok {
		if x, isStr := v.(string); !isStr || len(x) > maxURLBytes || !cleanText(x) {
			fail("options.icon_url must be a string of at most %d bytes", maxURLBytes)
		}
	}
	return out, errs
}
