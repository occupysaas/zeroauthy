package federation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// ErrProfile reports a provider profile that cannot be used.
var ErrProfile = errors.New("federation: invalid provider profile")

// Profile limits from the inventory.
const (
	maxProfileBytes  = 65536
	maxMetadataBytes = 16384
	maxMetadataDepth = 8
	maxPictureBytes  = 2048
)

// Profile is a normalized provider profile. Optional root attributes are
// pointers: nil means the provider did not supply the field, which never
// erases a stored value.
type Profile struct {
	Subject       string
	Email         *string
	EmailVerified *bool
	Name          *string
	Nickname      *string
	GivenName     *string
	FamilyName    *string
	Picture       *string
	// UserMetadata is set only from an explicit bounded object.
	UserMetadata map[string]any
}

// rootStrings are the optional root string attributes with their character
// limits.
var rootStrings = []struct {
	key   string
	limit int
	field func(*Profile) **string
}{
	{"email", 254, func(p *Profile) **string { return &p.Email }},
	{"name", 300, func(p *Profile) **string { return &p.Name }},
	{"nickname", 300, func(p *Profile) **string { return &p.Nickname }},
	{"given_name", 150, func(p *Profile) **string { return &p.GivenName }},
	{"family_name", 150, func(p *Profile) **string { return &p.FamilyName }},
}

// forbiddenProfileKeys are local attributes a provider profile may not set.
var forbiddenProfileKeys = []string{
	"app_metadata", "blocked", "identities", "password", "password_hash",
	"roles", "permissions", "scope", "scopes", "org_id", "organization",
	"authorization", "provider", "connection", "isSocial", "logins_count",
	"last_login", "last_ip", "created_at", "updated_at",
}

var pollutionKeys = []string{"__proto__", "constructor", "prototype"}

// NormalizeProfile validates a provider profile JSON object (user_id is the
// subject) and returns its typed form. Unmapped claims are ignored.
func NormalizeProfile(raw json.RawMessage) (Profile, error) {
	var p Profile
	if len(raw) > maxProfileBytes {
		return p, fmt.Errorf("%w: larger than %d bytes", ErrProfile, maxProfileBytes)
	}
	if !utf8.Valid(raw) {
		return p, fmt.Errorf("%w: not valid UTF-8", ErrProfile)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return p, fmt.Errorf("%w: not a JSON object", ErrProfile)
	}
	if dec.More() {
		return p, fmt.Errorf("%w: trailing data", ErrProfile)
	}
	for _, k := range forbiddenProfileKeys {
		if _, ok := m[k]; ok {
			return p, fmt.Errorf("%w: %s cannot be set by a provider", ErrProfile, k)
		}
	}

	switch v := m["user_id"].(type) {
	case string:
		p.Subject = v
	case json.Number:
		// Providers commonly return numeric IDs; only integers are stable.
		if _, err := strconv.ParseInt(v.String(), 10, 64); err != nil {
			return p, fmt.Errorf("%w: user_id must be a string or integer", ErrProfile)
		}
		p.Subject = v.String()
	default:
		return p, fmt.Errorf("%w: user_id is required", ErrProfile)
	}
	if err := ValidateSubject(p.Subject); err != nil {
		return p, err
	}

	for _, f := range rootStrings {
		v, ok := m[f.key]
		if !ok {
			continue
		}
		s, err := profileString(f.key, v, f.limit)
		if err != nil {
			return p, err
		}
		*f.field(&p) = &s
	}
	if v, ok := m["email_verified"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return p, fmt.Errorf("%w: email_verified must be a boolean", ErrProfile)
		}
		p.EmailVerified = &b
	}
	if v, ok := m["picture"]; ok {
		s, err := profileString("picture", v, 0)
		if err != nil {
			return p, err
		}
		u, perr := url.Parse(s)
		if len(s) > maxPictureBytes || perr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return p, fmt.Errorf("%w: picture must be an absolute https URL of at most %d bytes", ErrProfile, maxPictureBytes)
		}
		p.Picture = &s
	}
	if v, ok := m["user_metadata"]; ok {
		md, isObj := v.(map[string]any)
		if !isObj {
			return p, fmt.Errorf("%w: user_metadata must be an object", ErrProfile)
		}
		if depth(md) > maxMetadataDepth || hasPollution(md) {
			return p, fmt.Errorf("%w: user_metadata is too deep or has a reserved key", ErrProfile)
		}
		enc, err := json.Marshal(md)
		if err != nil || len(enc) > maxMetadataBytes {
			return p, fmt.Errorf("%w: user_metadata is larger than %d bytes", ErrProfile, maxMetadataBytes)
		}
		// Re-decode so numbers take the store's float64 form.
		var clean map[string]any
		if err := json.Unmarshal(enc, &clean); err != nil {
			return p, fmt.Errorf("%w: user_metadata is invalid", ErrProfile)
		}
		p.UserMetadata = clean
	}
	return p, nil
}

// ValidateSubject checks an upstream subject: nonempty valid UTF-8 without
// NUL, at most 1024 bytes. Bytes and case are preserved by callers.
func ValidateSubject(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("%w: user_id is empty", ErrProfile)
	case len(s) > rules.MaxSubjectBytes:
		return fmt.Errorf("%w: user_id is longer than %d bytes", ErrProfile, rules.MaxSubjectBytes)
	case !utf8.ValidString(s) || strings.ContainsRune(s, 0):
		return fmt.Errorf("%w: user_id must be UTF-8 without NUL", ErrProfile)
	}
	return nil
}

func profileString(key string, v any, limit int) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s must be a string", ErrProfile, key)
	}
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("%w: %s contains NUL", ErrProfile, key)
	}
	if limit > 0 && utf8.RuneCountInString(s) > limit {
		return "", fmt.Errorf("%w: %s is longer than %d characters", ErrProfile, key, limit)
	}
	return s, nil
}

func depth(v any) int {
	switch x := v.(type) {
	case map[string]any:
		d := 0
		for _, e := range x {
			d = max(d, depth(e))
		}
		return d + 1
	case []any:
		d := 0
		for _, e := range x {
			d = max(d, depth(e))
		}
		return d + 1
	}
	return 0
}

func hasPollution(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range slices.Collect(maps.Keys(x)) {
			if slices.Contains(pollutionKeys, k) || hasPollution(x[k]) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasPollution(e) {
				return true
			}
		}
	}
	return false
}
