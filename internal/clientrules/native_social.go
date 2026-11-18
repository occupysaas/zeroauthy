package clientrules

import (
	"encoding/json"
	"errors"
)

// ParseNativeSocialLogin validates the closed public provider objects.
// An omitted provider is disabled; an explicitly named provider requires enabled.
func ParseNativeSocialLogin(raw json.RawMessage) (map[string]bool, error) {
	var providers map[string]json.RawMessage
	if json.Unmarshal(raw, &providers) != nil || providers == nil {
		return nil, errors.New("must be an object")
	}
	for name := range providers {
		if name != "apple" && name != "facebook" && name != "google" {
			return nil, errors.New("unknown native social provider")
		}
	}
	out := map[string]bool{}
	for _, name := range []string{"apple", "facebook", "google"} {
		raw, ok := providers[name]
		if !ok {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) != 1 {
			return nil, errors.New("provider must be an object")
		}
		if _, ok := fields["enabled"]; !ok {
			return nil, errors.New("enabled is required")
		}
		enabled := false
		if raw, ok := fields["enabled"]; ok {
			var value *bool
			if json.Unmarshal(raw, &value) != nil || value == nil {
				return nil, errors.New("enabled must be a boolean")
			}
			enabled = *value
		}
		out[name] = enabled
	}
	return out, nil
}
