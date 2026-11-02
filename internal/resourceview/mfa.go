package resourceview

import "github.com/zeroauthy/zeroauthy/internal/store"

// Multifactor is a derived public value. Recovery alone is not enrollment.
func Multifactor(methods []store.Authenticator) []string {
	for _, a := range methods {
		if a.Confirmed && a.Type != "recovery-code" {
			return []string{"guardian"}
		}
	}
	return []string{}
}
func UserWithMFA(u *store.User, methods []store.Authenticator) map[string]any {
	out := User(u)
	out["multifactor"] = Multifactor(methods)
	return out
}
