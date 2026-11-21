package claims

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

const MaxRequestBytes = 4096
const ACRMultiFactor = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"

type Request struct {
	IDToken  map[string]*Requested
	UserInfo map[string]*Requested
}

type Requested struct {
	Essential bool
	Value     any
	Values    []any
}

// ParseRequest implements Core section 5.5. Unknown members are ignored.
// Failures never include the claim values, which can contain personal data.
func ParseRequest(raw string) (*Request, error) {
	if raw == "" {
		return nil, nil
	}
	invalid := errors.New("invalid_request: malformed claims parameter")
	if len(raw) > MaxRequestBytes || !utf8.ValidString(raw) {
		return nil, invalid
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &root); err != nil || root == nil {
		return nil, invalid
	}
	result := &Request{}
	for _, target := range []struct {
		name string
		dest *map[string]*Requested
	}{
		{"id_token", &result.IDToken}, {"userinfo", &result.UserInfo},
	} {
		data, present := root[target.name]
		if !present {
			continue
		}
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(data, &entries); err != nil || entries == nil {
			return nil, invalid
		}
		parsed := make(map[string]*Requested, len(entries))
		for name, entry := range entries {
			if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
				parsed[name] = nil
				continue
			}
			var properties map[string]json.RawMessage
			if err := json.Unmarshal(entry, &properties); err != nil || properties == nil {
				return nil, invalid
			}
			claim := &Requested{}
			if value, ok := properties["essential"]; ok {
				if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
					return nil, invalid
				}
				claim.Essential = bytes.Equal(value, []byte("true"))
			}
			value, hasValue := properties["value"]
			values, hasValues := properties["values"]
			if hasValue && hasValues {
				return nil, invalid
			}
			if hasValue {
				decoder := json.NewDecoder(bytes.NewReader(value))
				decoder.UseNumber()
				if err := decoder.Decode(&claim.Value); err != nil {
					return nil, invalid
				}
			}
			if hasValues {
				decoder := json.NewDecoder(bytes.NewReader(values))
				decoder.UseNumber()
				if err := decoder.Decode(&claim.Values); err != nil || claim.Values == nil {
					return nil, invalid
				}
			}
			parsed[name] = claim
		}
		*target.dest = parsed
	}
	return result, nil
}
