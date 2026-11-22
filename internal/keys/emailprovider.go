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
	sealed, err := w.Wrap(plaintext, emailProviderAAD("email-provider/v1", tenantID, provider))
	if err != nil {
		return nil, errEmailProviderEnvelope
	}
	return sealed, nil
}

// A tagged envelope seals only private credentials. The marker is longer than
// a legacy GCM nonce, and its version is also bound by the authenticated data.
const splitEmailProviderTag = "zeroauthy/email-provider/v2\x00"

func EmailProviderSecretsOnly(sealed []byte) bool {
	return bytes.HasPrefix(sealed, []byte(splitEmailProviderTag))
}

func SealEmailProviderSecrets(w Wrapper, tenantID, provider string, plaintext []byte) ([]byte, error) {
	if w == nil || tenantID == "" || provider == "" {
		return nil, errEmailProviderEnvelope
	}
	sealed, err := w.Wrap(plaintext, emailProviderAAD(splitEmailProviderTag, tenantID, provider))
	if err != nil {
		return nil, errEmailProviderEnvelope
	}
	return append([]byte(splitEmailProviderTag), sealed...), nil
}

// OpenEmailProvider decrypts credentials only under the exact tenant and
// provider identity used when they were sealed.
func OpenEmailProvider(w Wrapper, tenantID, provider string, sealed []byte) ([]byte, error) {
	if w == nil || tenantID == "" || provider == "" {
		return nil, errEmailProviderEnvelope
	}
	label := "email-provider/v1"
	if EmailProviderSecretsOnly(sealed) {
		label = splitEmailProviderTag
		sealed = sealed[len(splitEmailProviderTag):]
	}
	plaintext, err := w.Unwrap(sealed, emailProviderAAD(label, tenantID, provider))
	if err != nil {
		return nil, errEmailProviderEnvelope
	}
	return plaintext, nil
}

func emailProviderAAD(label, tenantID, provider string) []byte {
	var b bytes.Buffer
	for _, part := range []string{label, tenantID, provider} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(part)))
		b.WriteString(part)
	}
	return b.Bytes()
}
