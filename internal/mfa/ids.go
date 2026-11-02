package mfa

func NewMethodID(typ string) string { return typ + "|" + NewEnrollmentID() }
func NewEnrollmentID() string {
	return "dev_" + randomString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 20)
}
