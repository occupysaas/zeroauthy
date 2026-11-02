package mfa

import "strings"

func NewRecoveryCode() string { return randomString("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 24) }
func NormalizeRecoveryCode(s string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
}
