// Package customdomain owns the finite custom-domain validation contract. It is
// independent of tenant resolution, deployment configuration and TLS workers.
package customdomain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var ErrBodyTooLarge = errors.New("customdomain: request body exceeds 64 KiB")

type ReservedNames struct{ SystemHost, BaseDomain, OriginSuffix string }

// Field preserves omission, explicit null and an explicit zero value. Create
// defaults occupy Value while Present remains false for omitted fields.
type Field[T any] struct {
	Present, Null bool
	Value         T
}
type CreateInput struct {
	Domain, Type                                                                string
	VerificationMethod, TLSPolicy, CustomClientIPHeader, RelyingPartyIdentifier Field[string]
	DomainMetadata                                                              Field[map[string]string]
}
type PatchInput struct {
	TLSPolicy, CustomClientIPHeader, RelyingPartyIdentifier Field[string]
	DomainMetadata                                          Field[map[string]string]
}
type Term struct{ Field, Value string }
type Query []Term
type ListQuery struct {
	Query         Query
	Fields        []string
	IncludeFields bool
}

// NormalizeDNSName maps Unicode through the IDNA lookup profile before checking
// DNS byte limits. The pinned publicsuffix snapshot makes validation local and
// deterministic; no request performs a network suffix lookup.
func NormalizeDNSName(raw string) (string, error) {
	return normalizeName(raw, true)
}
func normalizeName(raw string, public bool) (string, error) {
	var name string
	var err error
	if public {
		name, err = hostname.NormalizeDNSName(raw)
	} else {
		name, err = hostname.NormalizeOperatorHost(raw)
	}
	if err != nil {
		return "", invalid(err.Error())
	}
	return name, nil
}
func invalid(message string) error {
	return fmt.Errorf("customdomain: %s: %w", message, store.ErrInvalid)
}

// readBody rejects unknown fields, duplicate properties, non-object bodies and
// trailing JSON values before callers interpret presence/null semantics.
func readBody(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	if len(raw) > 65536 {
		return nil, ErrBodyTooLarge
	}
	if !utf8.Valid(raw) {
		return nil, invalid("body must be UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid("body must be an object")
	}
	body := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, invalid("invalid JSON property")
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, invalid("unsupported property")
		}
		if _, exists := body[key]; exists {
			return nil, invalid("duplicate property")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, invalid("invalid JSON value")
		}
		body[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, invalid("invalid JSON object")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid("trailing JSON data")
	}
	return body, nil
}
func stringField(body map[string]json.RawMessage, key string, nullable bool) (Field[string], error) {
	raw, ok := body[key]
	if !ok {
		return Field[string]{}, nil
	}
	out := Field[string]{Present: true}
	if bytes.Equal(raw, []byte("null")) {
		if !nullable {
			return out, invalid(key + " cannot be null")
		}
		out.Null = true
		return out, nil
	}
	if err := json.Unmarshal(raw, &out.Value); err != nil {
		return out, invalid(key + " must be a string")
	}
	return out, nil
}
func metadataField(body map[string]json.RawMessage) (Field[map[string]string], error) {
	raw, ok := body["domain_metadata"]
	if !ok {
		return Field[map[string]string]{}, nil
	}
	out := Field[map[string]string]{Present: true}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) > 10 {
		return out, invalid("domain_metadata must contain at most ten string properties")
	}
	out.Value = make(map[string]string, len(values))
	for key, rawValue := range values {
		var value string
		if bytes.Equal(rawValue, []byte("null")) || json.Unmarshal(rawValue, &value) != nil || utf8.RuneCountInString(value) > 255 {
			return out, invalid("metadata values must be strings of at most 255 characters")
		}
		out.Value[key] = value
	}
	return out, nil
}

var patchFields = map[string]bool{"tls_policy": true, "custom_client_ip_header": true, "domain_metadata": true, "relying_party_identifier": true}
var createFields = map[string]bool{"domain": true, "type": true, "verification_method": true, "tls_policy": true, "custom_client_ip_header": true, "domain_metadata": true, "relying_party_identifier": true}

func settings(body map[string]json.RawMessage, domain string, patch bool) (PatchInput, error) {
	var out PatchInput
	var err error
	if out.TLSPolicy, err = stringField(body, "tls_policy", false); err != nil {
		return out, err
	}
	if out.TLSPolicy.Present && out.TLSPolicy.Value != "recommended" {
		return out, invalid("unsupported TLS policy")
	}
	if out.CustomClientIPHeader, err = stringField(body, "custom_client_ip_header", true); err != nil {
		return out, err
	}
	switch out.CustomClientIPHeader.Value {
	case "", "true-client-ip", "cf-connecting-ip", "x-forwarded-for", "x-azure-clientip":
	default:
		return out, invalid("unsupported client IP header")
	}
	if out.DomainMetadata, err = metadataField(body); err != nil {
		return out, err
	}
	if out.RelyingPartyIdentifier, err = stringField(body, "relying_party_identifier", patch); err != nil {
		return out, err
	}
	if out.RelyingPartyIdentifier.Present && !out.RelyingPartyIdentifier.Null {
		rp, e := NormalizeDNSName(out.RelyingPartyIdentifier.Value)
		if e != nil || !(domain == rp || strings.HasSuffix(domain, "."+rp)) {
			return out, invalid("relying party identifier must be the domain or a non-public-suffix ancestor")
		}
		out.RelyingPartyIdentifier.Value = rp
	}
	return out, nil
}
func ValidateCreate(raw []byte, reserved ReservedNames) (CreateInput, error) {
	var out CreateInput
	body, err := readBody(raw, createFields)
	if err != nil {
		return out, err
	}
	domain, err := stringField(body, "domain", false)
	if err != nil {
		return out, err
	}
	if out.Domain, err = NormalizeDNSName(domain.Value); err != nil {
		return out, err
	}
	for _, r := range []struct {
		name        string
		descendants bool
	}{{reserved.SystemHost, false}, {reserved.BaseDomain, true}, {reserved.OriginSuffix, true}} {
		if r.name == "" {
			continue
		}
		name, e := normalizeName(r.name, false)
		if e != nil {
			return out, invalid("invalid reserved DNS namespace")
		}
		if out.Domain == name || r.descendants && strings.HasSuffix(out.Domain, "."+name) {
			return out, invalid("reserved DNS namespace")
		}
	}
	kind, err := stringField(body, "type", false)
	if err != nil {
		return out, err
	}
	if kind.Value != "auth0_managed_certs" && kind.Value != "self_managed_certs" {
		return out, invalid("unsupported domain type")
	}
	out.Type = kind.Value
	if out.VerificationMethod, err = stringField(body, "verification_method", false); err != nil {
		return out, err
	}
	if out.VerificationMethod.Present && out.VerificationMethod.Value != "txt" {
		return out, invalid("unsupported verification method")
	}
	if !out.VerificationMethod.Present {
		out.VerificationMethod.Value = "txt"
	}
	s, err := settings(body, out.Domain, false)
	if err != nil {
		return out, err
	}
	out.TLSPolicy = s.TLSPolicy
	out.CustomClientIPHeader = s.CustomClientIPHeader
	out.DomainMetadata = s.DomainMetadata
	out.RelyingPartyIdentifier = s.RelyingPartyIdentifier
	if !out.TLSPolicy.Present {
		out.TLSPolicy.Value = "recommended"
	}
	if !out.CustomClientIPHeader.Present {
		out.CustomClientIPHeader.Value = "x-forwarded-for"
	}
	if !out.RelyingPartyIdentifier.Present {
		out.RelyingPartyIdentifier.Value = out.Domain
	}
	return out, nil
}
func ValidatePatch(raw []byte, current *store.CustomDomain) (PatchInput, error) {
	if current == nil {
		return PatchInput{}, invalid("current domain is required")
	}
	body, err := readBody(raw, patchFields)
	if err != nil {
		return PatchInput{}, err
	}
	return settings(body, current.Domain, true)
}

// ValidateDomainCount is called within the transaction that creates an API row.
// The existing count includes pending/failed API-managed rows; it does not reject
// reads or edits of grandfathered tenants above the cap.
func ValidateDomainCount(existing int) error {
	if existing < 0 || existing >= 100 {
		// A conflict (409), like the repository's atomic cap.
		return fmt.Errorf("customdomain: custom domain limit reached: %w", store.ErrConflict)
	}
	return nil
}

// ParseQuery accepts only literal quoted terms joined with AND. It deliberately
// does not implement escaping, wildcards, grouping or other Lucene operators.
func ParseQuery(raw string) (Query, error) {
	if len(raw) > 1024 {
		return nil, invalid("query exceeds 1024 bytes")
	}
	rest := strings.TrimSpace(raw)
	terms := Query{}
	for rest != "" {
		field, after, ok := strings.Cut(rest, ":\"")
		if !ok || (field != "domain" && field != "status" && field != "type") {
			return nil, invalid("unsupported query term")
		}
		end := strings.IndexByte(after, '"')
		if end < 0 {
			return nil, invalid("unterminated query value")
		}
		value := after[:end]
		if strings.ContainsAny(value, "\\*?\r\n") || !utf8.ValidString(value) {
			return nil, invalid("unsupported query syntax")
		}
		terms = append(terms, Term{Field: field, Value: value})
		if len(terms) > 8 {
			return nil, invalid("query exceeds eight terms")
		}
		rest = after[end+1:]
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, " AND ") {
			return nil, invalid("query terms require AND")
		}
		rest = strings.TrimSpace(rest[len(" AND "):])
		if rest == "" {
			return nil, invalid("missing query term")
		}
	}
	return terms, nil
}
func (q Query) Matches(row *store.CustomDomain) bool {
	if row == nil {
		return false
	}
	for _, term := range q {
		var value string
		switch term.Field {
		case "domain":
			value = row.Domain
		case "status":
			value = row.Status
		case "type":
			value = row.Type
		default:
			return false
		}
		if value != term.Value {
			return false
		}
	}
	return true
}

var publicFields = map[string]bool{
	"custom_domain_id": true, "domain": true, "primary": true, "status": true, "type": true,
	"origin_domain_name": true, "verification": true, "is_default": true, "custom_client_ip_header": true,
	"tls_policy": true, "domain_metadata": true, "certificate": true, "relying_party_identifier": true,
}

func ValidateListQuery(values url.Values) (ListQuery, error) {
	out := ListQuery{IncludeFields: true}
	for key, v := range values {
		if (key != "q" && key != "fields" && key != "include_fields" && key != "sort") || len(v) != 1 {
			return out, invalid("unsupported or repeated query parameter")
		}
	}
	if sort := values.Get("sort"); sort != "" && sort != "domain:1" {
		return out, invalid("unsupported sort")
	}
	var err error
	if out.Query, err = ParseQuery(values.Get("q")); err != nil {
		return out, err
	}
	if raw, ok := values["include_fields"]; ok {
		switch raw[0] {
		case "true":
		case "false":
			out.IncludeFields = false
		default:
			return out, invalid("include_fields must be boolean")
		}
	}
	if raw := values.Get("fields"); raw != "" {
		for _, field := range strings.Split(raw, ",") {
			field = strings.TrimSpace(field)
			if !publicFields[field] {
				return out, invalid("unsupported projection field")
			}
			out.Fields = append(out.Fields, field)
		}
	}
	return out, nil
}
