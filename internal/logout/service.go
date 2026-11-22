// Package logout coordinates session-end notifications. Token construction is
// separate from delivery so each durable retry can mint a fresh signed token.
package logout

import (
	"github.com/zeroauthy/zeroauthy/internal/compat"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"time"
)

type Service struct {
	HTTP                 *http.Client
	AllowPrivateNetworks bool
	Recorder             logs.Recorder
	Wrapper              keys.Wrapper
	Store                store.Store
	Keys                 *keys.Manager
	Compat               compat.Switches
	Now                  func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
