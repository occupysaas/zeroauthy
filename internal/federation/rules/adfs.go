package rules

import (
	"crypto/sha1" //nolint:gosec // Auth0's SHA-1 certificate thumbprints are identifiers.
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
)

// ADFS is the WS-Federation relying-party connection strategy (Plan 37b).
const ADFS = "adfs"

// ADFSMetadataPath is the federation metadata path an adfs_server host
// serves (Auth0's ADFS documentation).
const ADFSMetadataPath = "/FederationMetadata/2007-06/FederationMetadata.xml"

// MaxADFSMetadataBytes is Auth0's limit on federation metadata (128 KB).
const MaxADFSMetadataBytes = 128 << 10

// Email verification policies (should_trust_email_verified_connection).
const (
	NeverVerifiedEmails  = "never_set_emails_as_verified"
	AlwaysVerifiedEmails = "always_set_emails_as_verified"
)

// ADFSSettings are the validated adfs options.
type ADFSSettings struct {
	EntityID, SignInEndpoint, MetadataURL, UserIDAttribute string
	Thumbprints, Thumbprints384, PrevThumbprints           []string
	TrustEmailVerified                                     bool
}

// ADFSMetadataURL is the metadata URL of adfs_server: a host (or https URL
// without a path) gets the federation metadata path; an https URL with a
// path is used as given.
func ADFSMetadataURL(server string) string {
	if !strings.Contains(server, "://") {
		return "https://" + strings.TrimSuffix(server, "/") + ADFSMetadataPath
	}
	u, err := url.Parse(server)
	if err == nil && (u.Path == "" || u.Path == "/") {
		return strings.TrimSuffix(server, "/") + ADFSMetadataPath
	}
	return server
}

// ADFSThumbprints are a certificate's lowercase hex SHA-1 and SHA-384
// thumbprints.
func ADFSThumbprints(der []byte) (string, string) {
	s1 := sha1.Sum(der) //nolint:gosec // thumbprint identifier
	s384 := sha512.Sum384(der)
	return hex.EncodeToString(s1[:]), hex.EncodeToString(s384[:])
}

func hexList(v any, n int) ([]string, bool) {
	list, ok := v.([]any)
	if !ok || len(list) > 20 {
		return nil, false
	}
	out := []string{}
	for _, e := range list {
		s, ok := e.(string)
		s = strings.ToLower(strings.ReplaceAll(s, ":", ""))
		if _, err := hex.DecodeString(s); !ok || err != nil || s == "" || n > 0 && len(s) != n || len(s) > 96 {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// parseADFS validates adfs options (ConnectionOptionsADFS). Exactly one of
// adfs_server and fedMetadataXml is the source of the sign-in endpoint and
// signing certificates. With fedMetadataXml they are derived here; with
// adfs_server the Management API fetches the metadata before the write
// and puts signInEndpoint and the thumbprints into the options.
func parseADFS(in Input) (Settings, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	out := Settings{Strategy: ADFS, AuthenticationActive: true, ProfileSync: SyncOnEachLogin}
	a := &ADFSSettings{}
	out.ADFS = a
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
	str := func(k string, minLen, maxLen int) (string, bool) {
		v, ok := o[k]
		if !ok {
			return "", false
		}
		x, isStr := v.(string)
		if !isStr || len(x) < minLen || len(x) > maxLen || !cleanText(x) {
			fail("options.%s must be a string of %d to %d bytes", k, minLen, maxLen)
			return "", false
		}
		return x, true
	}
	server, hasServer := str("adfs_server", 1, maxURLBytes)
	xml, hasXML := o["fedMetadataXml"].(string)
	if _, named := o["fedMetadataXml"]; named && (!hasXML || xml == "" || len(xml) > 102400) {
		fail("options.fedMetadataXml must be a metadata document of at most 102400 bytes")
		hasXML = false
	}
	switch {
	case hasServer && hasXML:
		fail("options.adfs_server and options.fedMetadataXml cannot both be set")
	case !hasServer && !hasXML:
		fail("options.adfs_server or options.fedMetadataXml is required")
	case hasXML:
		md, err := samlcore.ParseWSFedMetadata([]byte(xml))
		if err != nil {
			fail("options.fedMetadataXml is not WS-Federation metadata with a signing certificate")
			break
		}
		if err := ValidateEndpoint(md.PassiveEndpoint, true); err != nil {
			fail("options.fedMetadataXml passive requestor endpoint %v", err)
		}
		a.SignInEndpoint = md.PassiveEndpoint
		for _, c := range md.SigningCerts {
			s1, s384 := ADFSThumbprints(c.Raw)
			a.Thumbprints = append(a.Thumbprints, s1)
			a.Thumbprints384 = append(a.Thumbprints384, s384)
		}
	case hasServer:
		a.MetadataURL = ADFSMetadataURL(server)
		if err := ValidateEndpoint(a.MetadataURL, false); err != nil {
			fail("options.adfs_server must be a host or https URL: %v", err)
		}
		if ep, ok := str("signInEndpoint", 1, maxURLBytes); ok {
			if err := ValidateEndpoint(ep, true); err != nil {
				fail("options.signInEndpoint %v", err)
			}
			a.SignInEndpoint = ep
		}
		if v, ok := o["thumbprints"]; ok {
			if a.Thumbprints, ok = hexList(v, 40); !ok {
				fail("options.thumbprints must be up to 20 SHA-1 hex thumbprints")
			}
		}
		if v, ok := o["thumbprints_sha384"]; ok {
			if a.Thumbprints384, ok = hexList(v, 96); !ok {
				fail("options.thumbprints_sha384 must be up to 20 SHA-384 hex thumbprints")
			}
		}
		if a.SignInEndpoint == "" || len(a.Thumbprints) == 0 && len(a.Thumbprints384) == 0 {
			fail("options.adfs_server metadata has not been read")
		}
	}
	if v, ok := o["prev_thumbprints"]; ok {
		if a.PrevThumbprints, ok = hexList(v, 0); !ok {
			fail("options.prev_thumbprints must be up to 20 hex thumbprints")
		}
	}
	if v, ok := str("entityId", 1, 128); ok {
		a.EntityID = v
	}
	if v, ok := str("user_id_attribute", 1, 128); ok {
		a.UserIDAttribute = v
	}
	if v, ok := str("should_trust_email_verified_connection", 1, 64); ok {
		switch v {
		case NeverVerifiedEmails:
		case AlwaysVerifiedEmails:
			a.TrustEmailVerified = true
		default:
			fail("options.should_trust_email_verified_connection must be %s or %s", NeverVerifiedEmails, AlwaysVerifiedEmails)
		}
	}
	str("tenant_domain", 1, 255)
	if v, ok := o["icon_url"]; ok {
		if x, isStr := v.(string); !isStr || len(x) > maxURLBytes || !cleanText(x) {
			fail("options.icon_url must be a string of at most %d bytes", maxURLBytes)
		}
	}
	if v, ok := o["domain_aliases"]; ok {
		aliases, err := ParseDomainAliases(v)
		if err != nil {
			fail("options.domain_aliases: %v", err)
		}
		out.DomainAliases = aliases
	}
	if v, ok := o["upstream_params"]; ok {
		if _, isObj := v.(map[string]any); !isObj {
			fail("options.upstream_params must be an object")
		}
	}
	return out, errs
}
