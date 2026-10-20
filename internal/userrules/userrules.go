// Package userrules holds the rules every user must follow, whoever writes
// it: the Management API, /dbconnections/signup and hosted signup. They
// are Auth0's, as observed (D-0043, observations U1-U3). CheckCreate and
// CheckPatch normalize and validate; ApplyPatch applies a patch to a user.
//
// The field checks that signup also needs (profile lengths, picture, the
// default name and nickname) live in package identity, which userrules
// calls, because identity cannot import this package (userrules needs
// identity's password policy). Signup therefore keeps calling
// identity.Database.Signup, which enforces the same functions.
package userrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Error codes Auth0's Management API uses for these rules.
const (
	CodeInvalidBody           = "invalid_body"
	CodeOperationNotSupported = "operation_not_supported"
)

// UserIDPrefix is prepended to every user_id a caller supplies.
const UserIDPrefix = store.StrategyDatabase + "|"

// MaxUserIDLength is the longest user_id a caller may supply, in
// characters, before the prefix.
const MaxUserIDLength = 255

// FieldError is one problem with a field. Code is Auth0's errorCode and is
// empty when Auth0 sends none (a weak password). Err, when set, is the
// underlying error (an *identity.PolicyError) and is reachable through
// errors.As.
type FieldError struct {
	Code, Message string
	Err           error
}

func (e *FieldError) Error() string { return e.Message }
func (e *FieldError) Unwrap() error { return e.Err }

func invalid(format string, a ...any) *FieldError {
	return &FieldError{Code: CodeInvalidBody, Message: fmt.Sprintf(format, a...)}
}

// Create is the body of POST /users. Strings are empty when absent;
// pointers are nil when absent.
type Create struct {
	Connection, Email, Username, Password, PhoneNumber, UserID string
	Name, GivenName, FamilyName, Nickname, Picture             string

	EmailVerified, PhoneVerified, Blocked *bool
	VerifyEmail                           *bool

	UserMetadata, AppMetadata map[string]any
}

// StoredUserID is the user_id to store: "auth0|" and the supplied value,
// even when the value already starts with "auth0|". Empty when the caller
// supplied none (the caller then generates one). The identity's own
// user_id is UserID, as supplied.
func (c *Create) StoredUserID() string {
	if c.UserID == "" {
		return ""
	}
	return UserIDPrefix + c.UserID
}

// Metadata is the metadata part of a patch. Set tells an absent member
// from an empty object: an absent one (Set false) leaves the stored
// metadata alone, {} (Set true, empty Value) empties it. A nil value in
// Value deletes that key. It decodes from a JSON object.
type Metadata struct {
	Set   bool
	Value map[string]any
}

// UnmarshalJSON decodes a JSON object; anything else is an error. A JSON
// null is Set with a nil Value, which ApplyPatch treats as emptying.
func (m *Metadata) UnmarshalJSON(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v == nil {
		v = map[string]any{}
	}
	m.Set, m.Value = true, v
	return nil
}

// Patch is the body of PATCH /users/{id}. Pointers mean "set"; nil means
// absent.
type Patch struct {
	Connection                                         string
	Email, Username, Password, PhoneNumber             *string
	Name, GivenName, FamilyName, Nickname, Picture     *string
	EmailVerified, PhoneVerified, Blocked, VerifyEmail *bool
	UserMetadata, AppMetadata                          Metadata
}

// DefaultPicture is identity.DefaultPicture, shared with signup.
func DefaultPicture(email string) string { return identity.DefaultPicture(email) }

// MissingConnectionMessage is Auth0's message for a body without
// connection (code invalid_body).
const MissingConnectionMessage = "Payload validation error: 'Missing required property: connection'."

// CheckMetadata validates one metadata object with identity's limits and
// returns a *FieldError.
func CheckMetadata(name string, m map[string]any) error {
	err := identity.CheckMetadata(name, m)
	if err == nil {
		return nil
	}
	return profileError(err)
}

const weakPassword = "PasswordStrengthError: Password is too weak"

func passwordError(err error) error {
	var pe *identity.PolicyError
	if errors.As(err, &pe) {
		return &FieldError{Message: weakPassword, Err: err}
	}
	return err
}

func checkEmail(email string) error {
	if err := identity.CheckEmail(email); err != nil {
		return invalid("Payload validation error: 'Object didn't pass validation for format email: %s' on property email (The user's email).", email)
	}
	return nil
}

func checkUserID(id string) error {
	if utf8.RuneCountInString(id) > MaxUserIDLength {
		return invalid("Payload validation error: 'String is too long (%d chars), maximum %d' on property user_id (The external user's id provided by the identity provider).", utf8.RuneCountInString(id), MaxUserIDLength)
	}
	if strings.IndexFunc(id, unicode.IsSpace) >= 0 {
		return invalid("Payload validation error: 'String does not match pattern ^\\S*$: %s' on property user_id (The external user's id provided by the identity provider).", id)
	}
	return nil
}

func profileError(err error) error {
	if err == nil {
		return nil
	}
	var pe *identity.PolicyError
	if errors.As(err, &pe) {
		return &FieldError{Code: CodeInvalidBody, Message: pe.Reason, Err: err}
	}
	return err
}

// CheckCreate normalizes in (lowercase email and username, default name,
// nickname and picture) and returns every problem found, as *FieldError.
// On a connection without usernames or phone numbers those fields are
// errors, not dropped. in is modified even when problems are returned.
func CheckCreate(c *store.Connection, in *Create) []error {
	var errs []error
	in.Email = loginid.Normalize(in.Email)
	in.Username = loginid.Normalize(in.Username)
	switch {
	case in.Email == "":
		errs = append(errs, invalid("Missing required property: email"))
	default:
		if err := checkEmail(in.Email); err != nil {
			errs = append(errs, err)
		}
	}
	if in.Username != "" && !c.RequiresUsername {
		errs = append(errs, &FieldError{Code: CodeOperationNotSupported, Message: "Cannot set username for connection without requires_username"})
	} else if c.RequiresUsername {
		if err := identity.CheckUsername(c, in.Username); err != nil {
			errs = append(errs, profileError(err))
		}
	}
	if in.PhoneNumber != "" {
		errs = append(errs, invalid(`"phone_number" is not allowed`))
	}
	if in.UserID != "" {
		if err := checkUserID(in.UserID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := profileError(identity.CheckProfile(in.GivenName, in.FamilyName, in.Name, in.Nickname, in.Picture)); err != nil {
		errs = append(errs, err)
	}
	in.Name, in.Nickname = identity.DefaultNames(in.Name, in.Nickname, in.Email, in.Username)
	if in.Picture == "" {
		in.Picture = DefaultPicture(in.Email)
	}
	if in.Password == "" {
		// Auth0's message for a missing password was not observed.
		errs = append(errs, invalid("Missing required property: password"))
	} else {
		person := identity.Person{
			Email: in.Email, Username: in.Username, Name: in.Name, GivenName: in.GivenName,
			FamilyName: in.FamilyName, Nickname: in.Nickname, UserMetadata: in.UserMetadata,
		}
		if err := identity.CheckPassword(c, person, in.Password, nil); err != nil {
			errs = append(errs, passwordError(err))
		}
	}
	for _, m := range []struct {
		name string
		v    map[string]any
	}{{"user_metadata", in.UserMetadata}, {"app_metadata", in.AppMetadata}} {
		if err := CheckMetadata(m.name, m.v); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// CheckPatch normalizes in (lowercase email and username) and returns every
// problem found. u is the user as stored. Password history is not checked
// here; the caller owns it.
func CheckPatch(c *store.Connection, u *store.User, in *Patch) []error {
	var errs []error
	if in.Email != nil {
		e := loginid.Normalize(*in.Email)
		in.Email = &e
		if err := checkEmail(e); err != nil {
			errs = append(errs, err)
		}
		if in.Password != nil {
			errs = append(errs, &FieldError{Code: CodeOperationNotSupported, Message: "Cannot update password and email simultaneously"})
		}
	}
	if in.Username != nil {
		n := loginid.Normalize(*in.Username)
		in.Username = &n
		if !c.RequiresUsername {
			errs = append(errs, &FieldError{Code: CodeOperationNotSupported, Message: "Cannot set username for connection without requires_username or attributes"})
		} else if err := identity.CheckUsername(c, n); err != nil {
			errs = append(errs, profileError(err))
		}
	}
	if in.PhoneNumber != nil {
		errs = append(errs, invalid(`"phone_number" is not allowed`))
	}
	str := func(p *string, def string) string {
		if p != nil {
			return *p
		}
		return def
	}
	if err := profileError(identity.CheckProfile(str(in.GivenName, ""), str(in.FamilyName, ""), str(in.Name, ""), str(in.Nickname, ""), str(in.Picture, ""))); err != nil {
		errs = append(errs, err)
	}
	if in.Password != nil {
		person := identity.PersonOf(u)
		if in.Email != nil {
			person.Email = *in.Email
		}
		if err := identity.CheckPassword(c, person, *in.Password, nil); err != nil {
			errs = append(errs, passwordError(err))
		}
	}
	for _, m := range []struct {
		name string
		v    Metadata
	}{{"user_metadata", in.UserMetadata}, {"app_metadata", in.AppMetadata}} {
		if err := CheckMetadata(m.name, m.v.Value); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// ApplyPatch copies the set fields of in onto u. It does not validate and
// does not touch the password or the stored version. An email that
// changes clears EmailVerified unless the patch sets email_verified.
func ApplyPatch(u *store.User, in *Patch) {
	if in.Email != nil && *in.Email != u.Email {
		u.Email = *in.Email
		u.EmailVerified = false
	}
	if in.EmailVerified != nil {
		u.EmailVerified = *in.EmailVerified
	}
	setStr := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	setStr(&u.Username, in.Username)
	setStr(&u.PhoneNumber, in.PhoneNumber)
	setStr(&u.Name, in.Name)
	setStr(&u.GivenName, in.GivenName)
	setStr(&u.FamilyName, in.FamilyName)
	setStr(&u.Nickname, in.Nickname)
	setStr(&u.Picture, in.Picture)
	if in.PhoneVerified != nil {
		u.PhoneVerified = *in.PhoneVerified
	}
	if in.Blocked != nil {
		u.Blocked = *in.Blocked
	}
	u.UserMetadata = mergeMetadata(u.UserMetadata, in.UserMetadata)
	u.AppMetadata = mergeMetadata(u.AppMetadata, in.AppMetadata)
}

// mergeMetadata merges patch into cur: top-level keys are set (nested
// objects replaced whole), a nil value deletes the key, and an empty patch
// empties the object. An absent patch returns cur.
func mergeMetadata(cur map[string]any, patch Metadata) map[string]any {
	if !patch.Set {
		return cur
	}
	if len(patch.Value) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(cur)+len(patch.Value))
	for k, v := range cur {
		out[k] = v
	}
	for k, v := range patch.Value {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}
