package keys

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var errEmailProviderEnvelope = errors.New("keys: email provider envelope operation failed")

// SealEmailProvider envelope-encrypts tenant provider credentials. The AAD
// uses length-prefixed fields so tenant/provider boundaries cannot collide.
func SealEmailProvider(w Wrapper, tenantID, provider string, plaintext []byte) ([]byte, error) {
	if w == nil || tenantID == "" || provider == "" {
		return nil, errEmailProviderEnvelope
	}
	sealed, err := w.Wrap(plaintext, emailProviderAAD(tenantID, provider))
	if err != nil {
		return nil, errEmailProviderEnvelope
	}
	return sealed, nil
}

// OpenEmailProvider decrypts credentials only under the exact tenant and
// provider identity used when they were sealed.
func OpenEmailProvider(w Wrapper, tenantID, provider string, sealed []byte) ([]byte, error) {
	if w == nil || tenantID == "" || provider == "" {
		return nil, errEmailProviderEnvelope
	}
	plaintext, err := w.Unwrap(sealed, emailProviderAAD(tenantID, provider))
	if err != nil {
		return nil, errEmailProviderEnvelope
	}
	return plaintext, nil
}

func emailProviderAAD(tenantID, provider string) []byte {
	var b bytes.Buffer
	for _, part := range []string{"email-provider/v1", tenantID, provider} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(part)))
		b.WriteString(part)
	}
	return b.Bytes()
}
