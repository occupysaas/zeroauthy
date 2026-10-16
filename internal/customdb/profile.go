package customdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/loginid"
)

// ErrBadProfile is a profile that breaks the rules in decodeProfile. The
// wrapping error names the offending field, never its value.
var ErrBadProfile = errors.New("customdb: script returned an invalid profile")

// maxUserIDBytes caps profile.user_id.
const maxUserIDBytes = 200

// Profile is a user as a login or get_user script returns it.
type Profile struct {
	UserID                                string // as returned (no "auth0|")
	Email, Username                       string // normalized lowercase
	EmailVerified                         bool
	Name, Nickname, GivenName, FamilyName string
	Picture                               string
	UserMetadata, AppMetadata             map[string]any
}

func badField(field string) error { return fmt.Errorf("%w: %s", ErrBadProfile, field) }

// decodeProfile validates a script's profile object.
func decodeProfile(raw json.RawMessage) (*Profile, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, badField("profile is not an object")
	}
	p := &Profile{}
	var err error
	if p.UserID, err = userID(m["user_id"]); err != nil {
		return nil, err
	}

	str := func(field string) (string, error) {
		switch v := m[field].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		}
		return "", badField(field)
	}
	if p.Email, err = str("email"); err != nil {
		return nil, err
	}
	if p.Email = loginid.Normalize(p.Email); p.Email != "" && !loginid.ValidEmail(p.Email) {
		return nil, badField("email")
	}
	if p.Username, err = str("username"); err != nil {
		return nil, err
	}
	if p.Username = loginid.Normalize(p.Username); p.Username != "" && !loginid.ValidUsername(p.Username) {
		return nil, badField("username")
	}
	if p.Email == "" && p.Username == "" {
		return nil, badField("email or username is required")
	}
	switch v := m["email_verified"].(type) {
	case nil:
	case bool:
		p.EmailVerified = v
	default:
		return nil, badField("email_verified")
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"name", &p.Name}, {"nickname", &p.Nickname}, {"given_name", &p.GivenName}, {"family_name", &p.FamilyName}} {
		if *f.dst, err = str(f.name); err != nil {
			return nil, err
		}
		if utf8.RuneCountInString(*f.dst) > loginid.MaxProfileFieldRunes {
			return nil, badField(f.name)
		}
	}
	if p.Picture, err = str("picture"); err != nil {
		return nil, err
	}
	if p.Picture != "" && !loginid.ValidPicture(p.Picture) {
		return nil, badField("picture")
	}
	if p.UserMetadata, err = metadata(m, "user_metadata"); err != nil {
		return nil, err
	}
	if p.AppMetadata, err = metadata(m, "app_metadata"); err != nil {
		return nil, err
	}
	return p, nil
}

// userID accepts a non-empty string or an integer JSON number of at most
// maxUserIDBytes, with no control characters and no '|'.
func userID(v any) (string, error) {
	var id string
	switch v := v.(type) {
	case string:
		id = v
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return "", badField("user_id")
		}
		id = strconv.FormatInt(n, 10)
	default:
		return "", badField("user_id")
	}
	if id == "" || len(id) > maxUserIDBytes || strings.ContainsRune(id, '|') ||
		strings.ContainsFunc(id, unicode.IsControl) || !utf8.ValidString(id) {
		return "", badField("user_id")
	}
	return id, nil
}

// metadata returns m[field] as an object; absent or null is nil.
func metadata(m map[string]any, field string) (map[string]any, error) {
	switch v := m[field].(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return normalizeNumbers(v).(map[string]any), nil
	}
	return nil, badField(field)
}

// normalizeNumbers turns the json.Numbers of a UseNumber decode back into
// float64, as a plain decode (and every storage driver) produces.
func normalizeNumbers(v any) any {
	switch v := v.(type) {
	case json.Number:
		f, _ := v.Float64()
		return f
	case map[string]any:
		for k, e := range v {
			v[k] = normalizeNumbers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = normalizeNumbers(e)
		}
	}
	return v
}
