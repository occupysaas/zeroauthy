// Package loginid holds the rules for emails, usernames and profile
// fields that both identity (sign-ups) and customdb (profiles returned by
// custom database scripts) enforce. It imports nothing from zeroauthy, so
// either package can use it.
package loginid

import (
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxEmailLength caps email addresses in bytes (RFC 5321's 254-octet path
// limit). See D-0020.
const MaxEmailLength = 254

// MaxProfileFieldRunes caps name, nickname, given_name and family_name.
const MaxProfileFieldRunes = 300

// MaxPictureLength caps a picture URL in runes.
const MaxPictureLength = 2000

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.+-]{1,64}$`)

// Normalize trims and lowercases an email or username.
func Normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidEmail reports whether a normalized email is a bare addr-spec of at
// most MaxEmailLength bytes.
func ValidEmail(email string) bool {
	if len(email) > MaxEmailLength {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && addr.Name == ""
}

// ValidUsername reports whether a normalized username is 1-64 characters
// of a-z, 0-9 and _ . + -. Usernames never contain '@'.
func ValidUsername(username string) bool { return usernamePattern.MatchString(username) }

// ValidPicture reports whether s is an https URL of at most
// MaxPictureLength characters.
func ValidPicture(s string) bool {
	u, err := url.Parse(s)
	return err == nil && utf8.RuneCountInString(s) <= MaxPictureLength && u.Scheme == "https" && u.Host != ""
}
