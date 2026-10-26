// Package certificates owns TLS asset coordination. Token signing certificates
// remain the responsibility of internal/keycert.
package certificates

import "github.com/zeroauthy/zeroauthy/internal/store"

// PublicData is the versioned public recovery metadata shared with storage.
// Private keys and credentials are always sealed in TLSAsset.Ciphertext.
type PublicData = store.TLSPublicData

// PublicDataVersion identifies the initial safe metadata schema. Consumers must
// reject unsupported versions before interpreting persistent recovery state.
const PublicDataVersion = 1
