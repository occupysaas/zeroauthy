package clientrules

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Add-on limits (Plan 37a, ClientAddonSAML in the Management OpenAPI).
const (
	maxSAMLString   = 1024
	maxSAMLURL      = 2048
	maxSAMLCert     = 16384
	maxSAMLMappings = 100
	maxSAMLNames    = 16
	maxSAMLLifetime = 86400
)

var (
	samlSignatureAlgorithms = map[string]bool{"rsa-sha256": true, "rsa-sha1": true}
	samlDigestAlgorithms    = map[string]bool{"sha256": true, "sha1": true}
	samlBindings            = map[string]bool{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST": true, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": true}
)

// strictObject decodes a JSON object, refusing duplicate keys and trailing
// content.
func strictObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("must be an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, errors.New("must be an object")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("must be an object")
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("must be an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("must be an object")
	}
	return out, nil
}

func isJSONNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func samlString(raw json.RawMessage, field string, max int) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("addons.samlp.%s must be a string", field)
	}
	if len(s) > max {
		return "", fmt.Errorf("addons.samlp.%s is too long", field)
	}
	return s, nil
}

func samlURL(raw json.RawMessage, field string) (string, error) {
	s, err := samlString(raw, field, maxSAMLURL)
	if err != nil || s == "" {
		return s, err
	}
	u, perr := url.Parse(s)
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("addons.samlp.%s must be an absolute http or https URL", field)
	}
	return s, nil
}

func samlBool(raw json.RawMessage, field string) (*bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return nil, fmt.Errorf("addons.samlp.%s must be a boolean", field)
	}
	return &b, nil
}

func samlNames(raw json.RawMessage, field string) ([]string, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" || len(one) > maxSAMLString {
			return nil, fmt.Errorf("addons.samlp.%s has an invalid name", field)
		}
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 || len(many) > maxSAMLNames {
		return nil, fmt.Errorf("addons.samlp.%s must be a name or 1 to %d names", field, maxSAMLNames)
	}
	for _, n := range many {
		if n == "" || len(n) > maxSAMLString {
			return nil, fmt.Errorf("addons.samlp.%s has an invalid name", field)
		}
	}
	return many, nil
}

// ParseCertificate reads a PEM certificate or base64 DER (Auth0 accepts both).
func ParseCertificate(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("not a certificate")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("not a certificate")
	}
	return x509.ParseCertificate(der)
}

// ParseAddons validates the addons object. null, {} and {"samlp": null}
// mean no add-ons. Add-ons other than samlp are refused (LR37a-5).
func ParseAddons(raw json.RawMessage) (*store.ClientAddons, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	fields, err := strictObject(raw)
	if err != nil {
		return nil, fmt.Errorf("addons %v", err)
	}
	for k := range fields {
		if k != "samlp" {
			return nil, fmt.Errorf("addons.%s is not supported", k)
		}
	}
	samlp, ok := fields["samlp"]
	if !ok || isJSONNull(samlp) {
		return nil, nil
	}
	s, err := parseSAMLAddon(samlp)
	if err != nil {
		return nil, err
	}
	return &store.ClientAddons{SAMLP: s}, nil
}

func parseSAMLAddon(raw json.RawMessage) (*store.SAMLAddon, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return nil, fmt.Errorf("addons.samlp %v", err)
	}
	s := &store.SAMLAddon{}
	for k, v := range fields {
		var err error
		switch k {
		case "mappings":
			var m map[string]json.RawMessage
			if json.Unmarshal(v, &m) != nil || m == nil {
				return nil, errors.New("addons.samlp.mappings must be an object")
			}
			if len(m) > maxSAMLMappings {
				return nil, errors.New("addons.samlp.mappings has too many entries")
			}
			s.Mappings = map[string][]string{}
			for field, names := range m {
				if field == "" || len(field) > maxSAMLString {
					return nil, errors.New("addons.samlp.mappings has an invalid field")
				}
				if s.Mappings[field], err = samlNames(names, "mappings."+field); err != nil {
					return nil, err
				}
			}
		case "audience":
			s.Audience, err = samlString(v, k, maxSAMLURL)
		case "recipient":
			s.Recipient, err = samlURL(v, k)
		case "destination":
			s.Destination, err = samlURL(v, k)
		case "issuer":
			s.Issuer, err = samlString(v, k, maxSAMLURL)
		case "createUpnClaim":
			s.CreateUpnClaim, err = samlBool(v, k)
		case "mapUnknownClaimsAsIs":
			s.MapUnknownClaimsAsIs, err = samlBool(v, k)
		case "passthroughClaimsWithNoMapping":
			s.PassthroughClaimsWithNoMapping, err = samlBool(v, k)
		case "mapIdentities":
			s.MapIdentities, err = samlBool(v, k)
		case "signResponse":
			s.SignResponse, err = samlBool(v, k)
		case "typedAttributes":
			s.TypedAttributes, err = samlBool(v, k)
		case "includeAttributeNameFormat":
			s.IncludeAttributeNameFormat, err = samlBool(v, k)
		case "signatureAlgorithm":
			if s.SignatureAlgorithm, err = samlString(v, k, 32); err == nil && !samlSignatureAlgorithms[s.SignatureAlgorithm] {
				err = errors.New("addons.samlp.signatureAlgorithm must be rsa-sha256 or rsa-sha1")
			}
		case "digestAlgorithm":
			if s.DigestAlgorithm, err = samlString(v, k, 32); err == nil && !samlDigestAlgorithms[s.DigestAlgorithm] {
				err = errors.New("addons.samlp.digestAlgorithm must be sha256 or sha1")
			}
		case "binding":
			if s.Binding, err = samlString(v, k, maxSAMLString); err == nil && !samlBindings[s.Binding] {
				err = errors.New("addons.samlp.binding must be the HTTP-POST or HTTP-Redirect binding")
			}
		case "lifetimeInSeconds":
			var n json.Number
			dec := json.NewDecoder(bytes.NewReader(v))
			dec.UseNumber()
			i, perr := int64(0), dec.Decode(&n)
			if perr == nil {
				i, perr = n.Int64()
			}
			if perr != nil || i < 1 || i > maxSAMLLifetime {
				return nil, fmt.Errorf("addons.samlp.lifetimeInSeconds must be an integer from 1 to %d", maxSAMLLifetime)
			}
			l := int(i)
			s.LifetimeInSeconds = &l
		case "nameIdentifierFormat":
			s.NameIdentifierFormat, err = samlString(v, k, maxSAMLString)
		case "nameIdentifierProbes":
			if json.Unmarshal(v, &s.NameIdentifierProbes) != nil || len(s.NameIdentifierProbes) > maxSAMLNames {
				return nil, fmt.Errorf("addons.samlp.nameIdentifierProbes must be up to %d strings", maxSAMLNames)
			}
			for _, p := range s.NameIdentifierProbes {
				if p == "" || len(p) > maxSAMLString {
					return nil, errors.New("addons.samlp.nameIdentifierProbes has an invalid entry")
				}
			}
		case "authnContextClassRef":
			s.AuthnContextClassRef, err = samlString(v, k, maxSAMLString)
		case "signingCert":
			if s.SigningCert, err = samlString(v, k, maxSAMLCert); err == nil && s.SigningCert != "" {
				if _, cerr := ParseCertificate(s.SigningCert); cerr != nil {
					err = errors.New("addons.samlp.signingCert must be a PEM or base64 DER certificate")
				}
			}
		case "logout":
			lf, lerr := strictObject(v)
			if lerr != nil {
				return nil, fmt.Errorf("addons.samlp.logout %v", lerr)
			}
			s.Logout = &store.SAMLAddonLogout{}
			for lk, lv := range lf {
				switch lk {
				case "callback":
					s.Logout.Callback, err = samlURL(lv, "logout.callback")
				case "slo_enabled":
					s.Logout.SLOEnabled, err = samlBool(lv, "logout.slo_enabled")
				default:
					err = fmt.Errorf("addons.samlp.logout.%s is not supported", lk)
				}
				if err != nil {
					return nil, err
				}
			}
		default:
			err = fmt.Errorf("addons.samlp.%s is not supported", k)
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// PublicAddons is the Management API form: a mapping to one name is a string.
func PublicAddons(a *store.ClientAddons) map[string]any {
	if a == nil || a.SAMLP == nil {
		return nil
	}
	raw, _ := json.Marshal(a.SAMLP)
	var samlp map[string]any
	_ = json.Unmarshal(raw, &samlp)
	if len(a.SAMLP.Mappings) > 0 {
		m := map[string]any{}
		for k, v := range a.SAMLP.Mappings {
			if len(v) == 1 {
				m[k] = v[0]
			} else {
				m[k] = v
			}
		}
		samlp["mappings"] = m
	}
	return map[string]any{"samlp": samlp}
}
