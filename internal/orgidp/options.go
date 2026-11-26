// Package orgidp maps the My Organization API's identity provider options
// (Auth0's My Organization OpenAPI 1.0.0, Idp<Strategy>OptionsRequest and
// ...OptionsResponse) to and from Management API connection options
// (Plan 42b Phase B, D-0221). Both directions are allowlists: unknown request
// members are refused and responses never carry secrets.
package orgidp

import (
	"fmt"
	"maps"
	"slices"
	"sort"
)

// Strategies are the OpenAPI's identity provider strategies.
var Strategies = []string{"adfs", "google-apps", "oidc", "okta", "pingfederate", "samlp", "waad"}

// Creatable are the strategies administrators may create: pingfederate is
// not a sign-in strategy in zeroauthy (D-0221).
var Creatable = []string{"adfs", "google-apps", "oidc", "okta", "samlp", "waad"}

type kind int

const (
	str kind = iota
	boolean
	object
)

type member struct {
	kind kind
	enum []string
	// conn is the connection option name when it differs.
	conn string
}

var (
	signAlg   = []string{"rsa-sha256", "rsa-sha1"}
	digestAlg = []string{"sha256", "sha1"}
	bindings  = []string{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}
)

// variant is one request shape: its members and the required ones.
type variant struct {
	members  map[string]member
	required []string
}

func samlCommon(extra map[string]member) map[string]member {
	m := map[string]member{
		"signSAMLRequest":    {kind: boolean},
		"signatureAlgorithm": {kind: str, enum: signAlg},
		"digestAlgorithm":    {kind: str, enum: digestAlg},
		"protocolBinding":    {kind: str, enum: bindings},
		"bindingMethod":      {kind: str},
		"idpInitiated":       {kind: object, conn: "idpinitiated"},
		"icon_url":           {kind: str},
	}
	maps.Copy(m, extra)
	return m
}

var oauthCommon = map[string]member{"client_id": {kind: str}, "client_secret": {kind: str}, "icon_url": {kind: str}}

func with(base map[string]member, k string, m member) map[string]member {
	out := maps.Clone(base)
	out[k] = m
	return out
}

// requests are the request variants per strategy; a request must match
// exactly one.
var requests = map[string][]variant{
	"oidc":        {{members: map[string]member{"type": {kind: str, enum: []string{"front_channel", "back_channel"}}, "client_id": {kind: str}, "client_secret": {kind: str}, "discovery_url": {kind: str}}, required: []string{"discovery_url", "client_id", "type"}}},
	"okta":        {{members: with(oauthCommon, "domain", member{kind: str}), required: []string{"domain", "client_id", "client_secret"}}},
	"google-apps": {{members: with(oauthCommon, "domain", member{kind: str}), required: []string{"domain", "client_id", "client_secret"}}},
	"waad":        {{members: with(oauthCommon, "tenant_domain", member{kind: str}), required: []string{"tenant_domain", "client_id", "client_secret"}}},
	"adfs": {
		{members: map[string]member{"adfs_server": {kind: str}}, required: []string{"adfs_server"}},
		{members: map[string]member{"fedMetadataXml": {kind: str}}, required: []string{"fedMetadataXml"}},
	},
	"samlp": {
		{members: samlCommon(map[string]member{"metadataUrl": {kind: str}, "signingCert": {kind: str}}), required: []string{"metadataUrl", "signSAMLRequest"}},
		{members: samlCommon(map[string]member{"signInEndpoint": {kind: str}, "signingCert": {kind: str}}), required: []string{"signInEndpoint", "signingCert", "signSAMLRequest"}},
	},
}

// defaults are connection options zeroauthy sets for a strategy (as the
// Plan 37c self-service assistant does).
var defaults = map[string]map[string]any{
	"oidc": {"scope": "openid profile email"},
	"okta": {"scope": "openid profile email"},
}

// ToConnection validates opts against strategy's request schema and
// returns the connection options to create with.
func ToConnection(strategy string, opts map[string]any) (map[string]any, error) {
	return toConnection(strategy, opts, false)
}

// ForUpdate is ToConnection for an update: the Secrets may be omitted, and
// the connection keeps its stored ones.
func ForUpdate(strategy string, opts map[string]any) (map[string]any, error) {
	return toConnection(strategy, opts, true)
}

func toConnection(strategy string, opts map[string]any, update bool) (map[string]any, error) {
	if strategy == "pingfederate" {
		return nil, fmt.Errorf("the pingfederate strategy is not supported by this server")
	}
	vs, ok := requests[strategy]
	if !ok {
		return nil, fmt.Errorf("strategy %q is not an identity provider strategy", strategy)
	}
	v := vs[0]
	if len(vs) > 1 {
		// Forms are told apart by their first required member.
		var picked []variant
		names := []string{}
		for _, f := range vs {
			names = append(names, f.required[0])
			if _, ok := opts[f.required[0]]; ok {
				picked = append(picked, f)
			}
		}
		if len(picked) != 1 {
			return nil, fmt.Errorf("options must have exactly one of %v", names)
		}
		v = picked[0]
	}
	out, err := v.apply(opts, update)
	if err != nil {
		return nil, err
	}
	for k, d := range defaults[strategy] {
		if _, set := out[k]; !set {
			out[k] = d
		}
	}
	return out, nil
}

func (v variant) apply(opts map[string]any, update bool) (map[string]any, error) {
	keys := slices.Sorted(maps.Keys(opts))
	out := map[string]any{}
	for _, k := range keys {
		m, ok := v.members[k]
		if !ok {
			return nil, fmt.Errorf("options.%s is not allowed", k)
		}
		val := opts[k]
		switch m.kind {
		case str:
			s, ok := val.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("options.%s must be a non-empty string", k)
			}
			if m.enum != nil && !slices.Contains(m.enum, s) {
				return nil, fmt.Errorf("options.%s must be one of %v", k, m.enum)
			}
		case boolean:
			if _, ok := val.(bool); !ok {
				return nil, fmt.Errorf("options.%s must be a boolean", k)
			}
		case object:
			if _, ok := val.(map[string]any); !ok {
				return nil, fmt.Errorf("options.%s must be an object", k)
			}
		}
		name := k
		if m.conn != "" {
			name = m.conn
		}
		out[name] = val
	}
	for _, k := range v.required {
		if _, ok := opts[k]; !ok && !(update && slices.Contains(Secrets, k)) {
			return nil, fmt.Errorf("options.%s is required", k)
		}
	}
	return out, nil
}

// responses are the response members per strategy: response name to
// connection option name.
var responses = map[string]map[string]string{
	"oidc":         {"type": "type", "client_id": "client_id", "discovery_url": "discovery_url"},
	"okta":         {"domain": "domain", "client_id": "client_id", "icon_url": "icon_url"},
	"google-apps":  {"domain": "domain", "client_id": "client_id", "icon_url": "icon_url"},
	"waad":         {"tenant_domain": "tenant_domain", "client_id": "client_id", "icon_url": "icon_url"},
	"adfs":         {"adfs_server": "adfs_server", "fedMetadataXml": "fedMetadataXml"},
	"samlp":        {"metadataUrl": "metadataUrl", "signInEndpoint": "signInEndpoint", "signSAMLRequest": "signSAMLRequest", "signatureAlgorithm": "signatureAlgorithm", "digestAlgorithm": "digestAlgorithm", "protocolBinding": "protocolBinding", "bindingMethod": "bindingMethod", "cert": "signingCert", "idpInitiated": "idpinitiated", "icon_url": "icon_url"},
	"pingfederate": {"pingFederateBaseUrl": "pingFederateBaseUrl", "signSAMLRequest": "signSAMLRequest", "signatureAlgorithm": "signatureAlgorithm", "digestAlgorithm": "digestAlgorithm", "cert": "signingCert", "idpInitiated": "idpinitiated", "icon_url": "icon_url"},
}

// FromConnection returns the response options of a connection of strategy:
// only the OpenAPI's response members, never secrets.
func FromConnection(strategy string, conn map[string]any) map[string]any {
	out := map[string]any{}
	names := responses[strategy]
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := conn[names[k]]; ok && v != nil {
			if k == "adfs_server" || k == "fedMetadataXml" {
				if s, _ := v.(string); s == "" {
					continue
				}
			}
			out[k] = v
		}
	}
	return out
}

// Secrets are the request members that are write-only: an update that
// omits them keeps the stored value.
var Secrets = []string{"client_secret"}
