package orgrules

import (
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// InvitationTTL validates a requested integer lifetime before converting it to
// a duration. A missing ttl_sec is represented by zero by the request decoder.
// Invitation expiry is independent of the generic email URL lifetime setting.
func InvitationTTL(seconds int64) (time.Duration, error) {
	if seconds < 0 || seconds > 2592000 {
		return 0, fmt.Errorf("invitation ttl_sec must be between 0 and 2592000: %w", store.ErrInvalid)
	}
	if seconds == 0 {
		seconds = 604800
	}
	return time.Duration(seconds) * time.Second, nil
}
