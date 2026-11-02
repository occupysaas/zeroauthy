package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

func NewTOTPSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20))
}
func TOTPURI(issuer, account, secret string) string {
	q := url.Values{"secret": {secret}, "issuer": {issuer}}
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + q.Encode()
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
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
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
