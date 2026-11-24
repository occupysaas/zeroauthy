package rules

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
	"strings"
)

// AD is the AD/LDAP connection strategy (Plan 38a): users authenticate
// through Auth0's AD/LDAP Connector.
const AD = "ad"

// ADManaged are the options the connector manages (LR38a-6): set by its
// registration, returned on reads, ignored on Management writes.
var ADManaged = []string{"agentIP", "agentMode", "agentVersion", "signInEndpoint", "certs", "thumbprints", "thumbprints_sha384"}

// MaxADCerts is the number of connector certificates kept (the OpenAPI
// maximum of certs, LR38a-5).
const MaxADCerts = 2

// ADSettings are the validated ad options.
type ADSettings struct {
	TenantDomain string
	IPs          []netip.Prefix
	Kerberos     bool
	CertAuth     bool
	// DisableChangePassword is disable_self_service_change_password.
	DisableChangePassword bool
	// SignInEndpoint is the connector's WS-Fed endpoint (Kerberos).
	SignInEndpoint string
	// Certs are the connectors' certificates (DER), newest first.
	Certs          [][]byte
	Thumbprints    []string
	Thumbprints384 []string
}

// ParseADCert reads a connector certificate: base64 DER (what the connector
// posts) or PEM (the OpenAPI's description).
func ParseADCert(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if b, _ := pem.Decode([]byte(s)); b != nil {
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("not a certificate")
		}
		der = b.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, fmt.Errorf("not base64 DER or PEM")
		}
	}
	return x509.ParseCertificate(der)
}

// ADClientInRanges reports whether ip is in one of the ranges.
func ADClientInRanges(ip string, ranges []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseAD validates ad options (ConnectionOptionsAD).
func parseAD(in Input) (Settings, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	out := Settings{Strategy: AD, AuthenticationActive: true, ProfileSync: SyncOnEachLogin}
	a := &ADSettings{}
	out.AD = a
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
	boolean := func(k string) bool {
		v, ok := o[k]
		if !ok {
			return false
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", k)
		}
		return b
	}
	a.Kerberos = boolean("kerberos")
	a.CertAuth = boolean("certAuth")
	a.DisableChangePassword = boolean("disable_self_service_change_password")
	boolean("disable_cache")
	boolean("agentMode")
	if v, ok := o["tenant_domain"]; ok {
		s, isStr := v.(string)
		if !isStr || len(s) < 1 || len(s) > 512 || !cleanText(s) || !validDNS(strings.ToLower(s)) {
			fail("options.tenant_domain must be a host name of at most 512 bytes")
		} else {
			a.TenantDomain = strings.ToLower(s)
		}
	}
	if v, ok := o["domain_aliases"]; ok {
		aliases, err := ParseDomainAliases(v)
		if err != nil {
			fail("options.domain_aliases: %v", err)
		}
		out.DomainAliases = aliases
	}
	if v, ok := o["ips"]; ok {
		list, isList := v.([]any)
		if !isList || len(list) > 256 {
			fail("options.ips must be an array of at most 256 addresses or CIDR ranges")
		}
		for _, e := range list {
			s, isStr := e.(string)
			if !isStr || len(s) < 2 || len(s) > 43 {
				fail("options.ips entries must be IP addresses or CIDR ranges")
				continue
			}
			if p, err := netip.ParsePrefix(s); err == nil {
				a.IPs = append(a.IPs, p.Masked())
			} else if ip, err := netip.ParseAddr(s); err == nil {
				a.IPs = append(a.IPs, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			} else {
				fail("options.ips entry %q is not an IP address or CIDR range", s)
			}
		}
	}
	for _, k := range []string{"agentIP", "agentVersion"} {
		if v, ok := o[k]; ok {
			if s, isStr := v.(string); !isStr || len(s) > 64 || !cleanText(s) {
				fail("options.%s must be a string of at most 64 bytes", k)
			}
		}
	}
	if v, ok := o["signInEndpoint"]; ok {
		a.SignInEndpoint = samlURL(v, "signInEndpoint", fail)
	}
	if v, ok := o["certs"]; ok {
		list, isList := v.([]any)
		if !isList || len(list) > MaxADCerts {
			fail("options.certs must be an array of at most %d certificates", MaxADCerts)
		}
		for _, e := range list {
			s, _ := e.(string)
			c, err := ParseADCert(s)
			if err != nil {
				fail("options.certs entry is not a certificate")
				continue
			}
			a.Certs = append(a.Certs, c.Raw)
			s1, s384 := ADFSThumbprints(c.Raw)
			a.Thumbprints = append(a.Thumbprints, s1)
			a.Thumbprints384 = append(a.Thumbprints384, s384)
		}
	}
	if v, ok := o["icon_url"]; ok {
		if x, isStr := v.(string); !isStr || len(x) > maxURLBytes || !cleanText(x) {
			fail("options.icon_url must be a string of at most %d bytes", maxURLBytes)
		}
	}
	if v, ok := o["upstream_params"]; ok {
		if _, isObj := v.(map[string]any); !isObj {
			fail("options.upstream_params must be an object")
		}
	}
	return out, errs
}
