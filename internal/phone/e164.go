package phone

import "github.com/zeroauthy/zeroauthy/internal/phonenumber"

var ErrInvalidPhone = phonenumber.ErrInvalidPhone

func NormalizeE164(raw, defaultRegion string) (string, error) {
	return phonenumber.NormalizeE164(raw, defaultRegion)
}
func CountryCode(e164 string) string { return phonenumber.CountryCode(e164) }

func Countries() []string { return phonenumber.Countries() }
