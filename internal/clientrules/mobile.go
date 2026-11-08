package clientrules

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ParseMobile accepts the documented ClientMobile types. Unknown properties
// are ignored for forward compatibility, as permitted by each public schema.
// App identifiers have no documented format constraint. Association consumers
// independently refuse unusable identities when constructing trust documents.
func ParseMobile(raw json.RawMessage) (*store.ClientMobile, error) {
	object := func(raw json.RawMessage) (map[string]json.RawMessage, error) {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || m == nil {
			return nil, errors.New("must be an object")
		}
		return m, nil
	}
	text := func(m map[string]json.RawMessage, k string, dst *string) error {
		raw, ok := m[k]
		if !ok {
			return nil
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, dst) != nil {
			return errors.New("mobile identity must be a string")
		}
		return nil
	}
	m, err := object(raw)
	if err != nil {
		return nil, err
	}
	mobile := &store.ClientMobile{}
	if raw, ok := m["ios"]; ok {
		ios, err := object(raw)
		if err != nil {
			return nil, err
		}
		mobile.IOS = &store.ClientMobileIOS{}
		if err = text(ios, "team_id", &mobile.IOS.TeamID); err != nil {
			return nil, err
		}
		if err = text(ios, "app_bundle_identifier", &mobile.IOS.AppBundleIdentifier); err != nil {
			return nil, err
		}
	}
	if raw, ok := m["android"]; ok {
		android, err := object(raw)
		if err != nil {
			return nil, err
		}
		mobile.Android = &store.ClientMobileAndroid{}
		if err = text(android, "app_package_name", &mobile.Android.AppPackageName); err != nil {
			return nil, err
		}
		if raw, ok := android["sha256_cert_fingerprints"]; ok {
			var entries []json.RawMessage
			if json.Unmarshal(raw, &entries) != nil || len(entries) == 0 {
				return nil, errors.New("fingerprints need at least one string")
			}
			for _, entry := range entries {
				var fp string
				if json.Unmarshal(entry, &fp) != nil || fp == "" {
					return nil, errors.New("fingerprints must be nonempty strings")
				}
				mobile.Android.SHA256CertFingerprints = append(mobile.Android.SHA256CertFingerprints, fp)
			}
		}
	}
	return mobile, nil
}
