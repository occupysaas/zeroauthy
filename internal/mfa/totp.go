package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func NewTOTPSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20))
}
func TOTPURI(issuer, account, secret string) string {
	q := url.Values{"secret": {secret}, "issuer": {issuer}}
	// The label has exactly one literal issuer separator; colons inside
	// either part are percent-encoded (Key URI format).
	label := func(v string) string { return strings.ReplaceAll(url.PathEscape(v), ":", "%3A") }
	return "otpauth://totp/" + label(issuer) + ":" + label(account) + "?" + q.Encode()
}
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(NormalizeTOTPSecret(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	current := now.Unix() / 30
	if now.Unix() < 0 && now.Unix()%30 != 0 {
		current--
	}
	for _, offset := range []int64{0, -1, 1} {
		step := current + offset
		if step < 0 {
			continue
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(step))
		h := hmac.New(sha1.New, key)
		h.Write(b[:])
		sum := h.Sum(nil)
		i := int(sum[len(sum)-1] & 15)
		n := binary.BigEndian.Uint32(sum[i:i+4]) & 0x7fffffff
		expected := fmt.Sprintf("%06d", n%1000000)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// NormalizeTOTPSecret canonicalizes imported or Management API base32 TOTP
// material before strict decoding: upper case, without spaces or trailing
// '=' padding. Other separators stay invalid rather than being guessed. It never logs or returns errors containing material.
func NormalizeTOTPSecret(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.ToUpper(s))
	return strings.TrimRight(s, "=")
}

// TOTPAccount is the authenticator-app account label: the user's email,
// else username, else user ID, so the label is never empty.
func TOTPAccount(u *store.User) string {
	switch {
	case u == nil:
		return ""
	case u.Email != "":
		return u.Email
	case u.Username != "":
		return u.Username
	}
	return u.UserID
}
