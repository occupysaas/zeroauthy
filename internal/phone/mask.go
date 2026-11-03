package phone

import "github.com/zeroauthy/zeroauthy/internal/phonerules"

// Mask hides all but the last four characters of a phone number. The rule has
// one source of truth, phonerules.MaskPhone (D-0060).
func Mask(e164 string) string { return phonerules.MaskPhone(e164) }
