package mfa

import (
	"crypto/rand"
	"io"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}
func randomString(alphabet string, n int) string {
	out := make([]byte, 0, n)
	limit := 256 - 256%len(alphabet)
	for len(out) < n {
		for _, b := range randomBytes(n - len(out)) {
			if int(b) < limit {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}
func NewEmailCode() string { return randomString("0123456789", 6) }
