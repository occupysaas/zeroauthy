package clientrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Limits on the WS-Fed add-on (Plan 37b, D-0140).
const (
	maxWSFedAddonBytes = 4096
	maxClientAliases   = 100
	maxClientAliasLen  = 1024
	maxFormTemplate    = 65536
)

// parseWSFedAddon accepts any JSON object of at most 4 KiB and keeps it
// compacted: the add-on's members have no effect (LR37b-4).
func parseWSFedAddon(raw json.RawMessage) (json.RawMessage, error) {
	if _, err := strictObject(raw); err != nil {
		return nil, fmt.Errorf("addons.wsfed %v", err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, errors.New("addons.wsfed must be an object")
	}
	if buf.Len() > maxWSFedAddonBytes {
		return nil, fmt.Errorf("addons.wsfed must be at most %d bytes", maxWSFedAddonBytes)
	}
	return buf.Bytes(), nil
}

// ParseClientAliases validates client_aliases: the realms accepted as
// wtrealm besides the client ID. null and [] clear them. Uniqueness within
// the tenant is the store's (LR37b-3); duplicates within the list are
// refused here.
func ParseClientAliases(raw json.RawMessage) ([]string, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("must be an array of strings")
	}
	if len(v) > maxClientAliases {
		return nil, fmt.Errorf("must have at most %d entries", maxClientAliases)
	}
	seen := make(map[string]bool, len(v))
	for _, a := range v {
		if a == "" || len(a) > maxClientAliasLen {
			return nil, fmt.Errorf("entries must be 1 to %d characters", maxClientAliasLen)
		}
		if strings.IndexFunc(a, unicode.IsControl) >= 0 {
			return nil, errors.New("entries must not contain control characters")
		}
		if seen[a] {
			return nil, fmt.Errorf("%q is listed twice", a)
		}
		seen[a] = true
	}
	if len(v) == 0 {
		return nil, nil
	}
	return v, nil
}

// ParseFormTemplate validates form_template, which is stored only (LR37b-5).
func ParseFormTemplate(raw json.RawMessage) (string, error) {
	if isJSONNull(raw) {
		return "", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", errors.New("must be a string")
	}
	if v == "" || len(v) > maxFormTemplate {
		return "", fmt.Errorf("must be 1 to %d characters", maxFormTemplate)
	}
	return v, nil
}
