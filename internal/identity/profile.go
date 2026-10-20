package identity

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultPicture is the picture a database user gets without one:
// Gravatar's, keyed by the MD5 of the lowercased, trimmed email, with
// Gravatar's built-in placeholder (D-0043). Empty without an email.
func DefaultPicture(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}
	sum := md5.Sum([]byte(email))
	return "https://s.gravatar.com/avatar/" + hex.EncodeToString(sum[:]) + "?s=480&r=pg&d=mp"
}

// MetadataLimits bounds one metadata object (user_metadata or
// app_metadata). Auth0 documents a total of 16 MB per user for each; its
// key-name rules are not published in full, so zeroauthy refuses empty keys
// and keys that start with '$' or '.' and nesting deeper than MaxDepth.
var MetadataLimits = struct {
	MaxBytes int // encoded JSON size of one metadata object
	MaxDepth int
}{MaxBytes: 16 * 1024 * 1024, MaxDepth: 100}

// CheckMetadata validates one metadata object; name is "user_metadata" or
// "app_metadata". It returns a *PolicyError.
func CheckMetadata(name string, m map[string]any) error {
	if len(m) == 0 {
		return nil
	}
	if err := checkMetadataKeys(name, m, 1); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return &PolicyError{Reason: name + " is not valid JSON"}
	}
	if len(b) > MetadataLimits.MaxBytes {
		return &PolicyError{Reason: fmt.Sprintf("%s is too large: at most %d bytes", name, MetadataLimits.MaxBytes)}
	}
	return nil
}

func checkMetadataKeys(name string, v any, depth int) error {
	if depth > MetadataLimits.MaxDepth {
		return &PolicyError{Reason: name + " is nested too deeply"}
	}
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if k == "" || k[0] == '$' || k[0] == '.' {
				return &PolicyError{Reason: fmt.Sprintf("%s has an invalid key name %q", name, k)}
			}
			if err := checkMetadataKeys(name, e, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := checkMetadataKeys(name, e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
