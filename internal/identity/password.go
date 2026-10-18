package identity

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity/dictionary"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Person is what zeroauthy holds about the user a password is for, for the
// personal data rule. Empty fields are ignored.
type Person struct {
	Email, Username, Name, GivenName, FamilyName, Nickname string
	PhoneNumber                                            string
	// UserMetadata is the user's user_metadata; only the string values of
	// name, first and last are used.
	UserMetadata map[string]any
}

// PersonOf describes an existing user.
func PersonOf(u *store.User) Person {
	if u == nil {
		return Person{}
	}
	return Person{
		Email: u.Email, Username: u.Username, Name: u.Name, GivenName: u.GivenName,
		FamilyName: u.FamilyName, Nickname: u.Nickname, UserMetadata: u.UserMetadata,
	}
}

// minProfileValue is the shortest value of a profile field the personal
// data rule looks for: shorter ones would refuse far too many passwords.
const minProfileValue = 3

// EffectivePassword is the password as it is hashed and verified on c. A
// connection whose max_length_exceeded is "truncate" cuts a password of more
// than MaxPasswordBytes bytes at that length (never inside a UTF-8
// sequence), so a longer password and its truncation are the same password.
// Every place that hashes or verifies a password uses it; otherwise the
// password is returned as given.
func EffectivePassword(c *store.Connection, password string) string {
	if c.PasswordOptions.Complexity.MaxLengthExceeded != store.MaxLengthTruncate || len(password) <= MaxPasswordBytes {
		return password
	}
	n := MaxPasswordBytes
	for n > 0 && !utf8.RuneStart(password[n]) {
		n--
	}
	return password[:n]
}

// typeNames are the names shown for the character types.
var typeNames = map[string]string{
	store.CharacterTypeUppercase: "uppercase letters",
	store.CharacterTypeLowercase: "lowercase letters",
	store.CharacterTypeNumber:    "digits",
	store.CharacterTypeSpecial:   "symbols",
}

// CheckPassword enforces the password options of connection c on candidate,
// the password person is setting: complexity, then the dictionary, personal
// data, and last the user's password history, given as the stored hashes
// (newest first; LoadHistory returns them). It returns a *PolicyError.
// When the connection truncates long passwords, candidate is checked as
// EffectivePassword returns it; callers hash that, too.
func CheckPassword(c *store.Connection, person Person, candidate string, history [][]byte) error {
	candidate = EffectivePassword(c, candidate)
	o := c.PasswordOptions
	if err := checkComplexity(o.Complexity, candidate); err != nil {
		return err
	}
	if o.Dictionary.Active && inDictionary(o.Dictionary, candidate) {
		return &PolicyError{Reason: "password is too common", Key: i18n.KeyPasswordDictionary}
	}
	if o.ProfileData.Active && hasPersonalInfo(o.ProfileData.BlockedFields, person, candidate) {
		return &PolicyError{Reason: "password must not contain personal information", Key: i18n.KeyPasswordPersonalInfo}
	}
	if o.History.Active && o.History.Size > 0 {
		for _, h := range history[:min(len(history), o.History.Size)] {
			if ok, err := secrets.Verify(string(h), candidate); err == nil && ok {
				return &PolicyError{
					Reason: "password was used recently", Key: i18n.KeyPasswordInHistory, Err: ErrPasswordInHistory,
				}
			}
		}
	}
	return nil
}

func checkComplexity(p store.PasswordComplexity, password string) error {
	minLen := p.MinLength
	if minLen <= 0 {
		minLen = defaultMinPasswordLength
	}
	if len(password) > MaxPasswordBytes {
		return &PolicyError{Reason: "password is too long", Key: i18n.KeyPasswordTooLong}
	}
	if utf8.RuneCountInString(password) < minLen {
		return &PolicyError{
			Reason: fmt.Sprintf("password must be at least %d characters", minLen),
			Key:    i18n.KeyPasswordTooShort, Vars: []string{"min", strconv.Itoa(minLen)},
		}
	}
	if err := checkClasses(p, password); err != nil {
		return err
	}
	if p.IdenticalCharacters == store.PasswordBlock && hasIdentical(password) {
		return &PolicyError{
			Reason: "password must not contain three or more identical characters in a row",
			Key:    i18n.KeyPasswordIdentical,
		}
	}
	if p.SequentialCharacters == store.PasswordBlock && hasSequential(password) {
		return &PolicyError{
			Reason: "password must not contain three or more sequential characters, such as abc or 321",
			Key:    i18n.KeyPasswordSequential,
		}
	}
	return nil
}

func checkClasses(p store.PasswordComplexity, password string) error {
	if len(p.CharacterTypes) == 0 && p.MinCharacterClasses <= 0 {
		return nil
	}
	has := map[string]bool{}
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			has[store.CharacterTypeLowercase] = true
		case unicode.IsUpper(r):
			has[store.CharacterTypeUppercase] = true
		case unicode.IsDigit(r):
			has[store.CharacterTypeNumber] = true
		default:
			has[store.CharacterTypeSpecial] = true
		}
	}
	// A password must hold every listed type (rule "all"), or any three of
	// the four ("three_of_four"), and at least MinCharacterClasses of the
	// four whichever they are.
	threeOfFour := len(p.CharacterTypes) > 0 && p.CharacterTypeRule == store.CharacterTypeRuleThreeOfFour
	if len(p.CharacterTypes) > 0 && !threeOfFour {
		var names []string
		missing := false
		for _, t := range store.CharacterTypes { // in the fixed order
			if slices.Contains(p.CharacterTypes, t) {
				names = append(names, typeNames[t])
				missing = missing || !has[t]
			}
		}
		if missing {
			list := strings.Join(names, ", ")
			return &PolicyError{
				Reason: "password must contain " + list, Key: i18n.KeyPasswordTypes, Vars: []string{"types", list},
			}
		}
	}
	need := p.MinCharacterClasses
	if threeOfFour {
		need = max(need, 3)
	}
	if len(has) < need {
		return &PolicyError{
			Reason: fmt.Sprintf(
				"password must contain at least %d of: lowercase letters, uppercase letters, digits, symbols", need),
			Key: i18n.KeyPasswordClasses, Vars: []string{"count", strconv.Itoa(need)},
		}
	}
	return nil
}

// hasIdentical reports three or more equal characters in a row.
func hasIdentical(s string) bool {
	var prev rune
	run := 0
	for _, r := range s {
		if run > 0 && r == prev {
			run++
		} else {
			run = 1
		}
		if run >= 3 {
			return true
		}
		prev = r
	}
	return false
}

// seqClass is 'a' for a letter A-Z/a-z, 'd' for a digit 0-9, else 0.
func seqClass(r rune) byte {
	switch {
	case r >= '0' && r <= '9':
		return 'd'
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		return 'a'
	}
	return 0
}

// hasSequential reports three or more letters (ignoring case) or digits in
// a row, each one after the last in the alphabet or in the digits, either
// ascending ("abc", "123") or descending ("cba", "321"). Only the ASCII
// letters and digits count; the alphabet does not wrap, and a letter never
// follows a digit.
func hasSequential(s string) bool {
	var prev rune
	step, run := 0, 1
	for _, r := range s {
		r = unicode.ToLower(r)
		d := int(r - prev)
		if prev != 0 && (d == 1 || d == -1) && seqClass(r) != 0 && seqClass(r) == seqClass(prev) {
			if step == d {
				run++
			} else {
				step, run = d, 2
			}
		} else {
			step, run = 0, 1
		}
		if run >= 3 {
			return true
		}
		prev = r
	}
	return false
}

func inDictionary(d store.PasswordDictionary, candidate string) bool {
	if d.Default != "" && dictionary.InDefault(d.Default, candidate) {
		return true
	}
	folded := dictionary.Fold(candidate)
	for _, w := range d.Custom {
		if w = strings.TrimSpace(w); w != "" && dictionary.Fold(w) == folded {
			return true
		}
	}
	return false
}

// profileValues returns the values of the blocked fields person has.
func profileValues(blocked []string, p Person) []string {
	var out []string
	meta := func(k string) string {
		s, _ := p.UserMetadata[k].(string)
		return s
	}
	for _, f := range blocked {
		switch f {
		case "name":
			out = append(out, p.Name)
		case "username":
			out = append(out, p.Username)
		case "nickname":
			out = append(out, p.Nickname)
		case "email":
			out = append(out, p.Email)
			if local, _, ok := strings.Cut(p.Email, "@"); ok {
				out = append(out, local)
			}
		case "phone_number":
			out = append(out, p.PhoneNumber)
		case "user_metadata.name":
			out = append(out, meta("name"))
		case "user_metadata.first":
			out = append(out, meta("first"))
		case "user_metadata.last":
			out = append(out, meta("last"))
		}
	}
	return out
}

func hasPersonalInfo(blocked []string, p Person, candidate string) bool {
	folded := dictionary.Fold(candidate)
	for _, v := range profileValues(blocked, p) {
		v = strings.TrimSpace(v)
		if utf8.RuneCountInString(v) < minProfileValue {
			continue
		}
		if strings.Contains(folded, dictionary.Fold(v)) {
			return true
		}
	}
	return false
}

// LoadHistory returns the stored password hashes CheckPassword compares
// with, newest first: the newest Size when c's history rule is active,
// nothing otherwise.
func LoadHistory(ctx context.Context, st store.Store, c *store.Connection, userID string) ([][]byte, error) {
	h := c.PasswordOptions.History
	if !h.Active || h.Size <= 0 {
		return nil, nil
	}
	list, err := st.PasswordHistories().List(ctx, c.TenantID, userID)
	if err != nil {
		return nil, err
	}
	return list[:min(len(list), h.Size)], nil
}

// RecordPassword stores hash (secrets.Hash of EffectivePassword) as the
// user's newest password and trims the history to the connection's size.
// When the history rule is inactive (or has no valid size) it stores and
// deletes nothing, so turning the rule off and on again does not lose what
// was recorded.
func RecordPassword(ctx context.Context, st store.Store, c *store.Connection, userID, hash string) error {
	h := c.PasswordOptions.History
	if !h.Active || h.Size <= 0 {
		return nil
	}
	return st.PasswordHistories().Add(ctx, c.TenantID, userID, []byte(hash), h.Size)
}
