// Command m33b-legacy-store is the Plan 33b journey 12 fixture: the sample
// memory plugin as a plugin built before webauthn.v1 would behave. Its
// WebAuthnCapabilities answer carries no version, so the host latches
// WebAuthn unavailable; every other capability is the memory driver's own.
package main

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
)

type legacy struct{ *memory.Store }

func (legacy) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

func main() { storeplugin.Serve(legacy{memory.New()}) }
