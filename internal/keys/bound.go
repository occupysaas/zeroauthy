package keys

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var errBoundEnvelope = errors.New("keys: bound envelope operation failed")

// SealBound envelope-encrypts plaintext under AAD made of label (which names
// the format and its version) and fields, length-prefixed so that no field
// boundary can collide. Errors never include the plaintext.
func SealBound(w Wrapper, label string, fields []string, plaintext []byte) ([]byte, error) {
	if w == nil || label == "" {
		return nil, errBoundEnvelope
	}
	out, err := seal(w, plaintext, boundAAD(label, fields))
	if err != nil {
		return nil, errBoundEnvelope
	}
	return out, nil
}

// OpenBound reverses SealBound under exactly the same label and fields.
func OpenBound(w Wrapper, label string, fields []string, sealed []byte) ([]byte, error) {
	if w == nil || label == "" || len(sealed) == 0 {
		return nil, errBoundEnvelope
	}
	out, err := unseal(w, sealed, boundAAD(label, fields))
	if err != nil {
		return nil, errBoundEnvelope
	}
	return out, nil
}

func boundAAD(label string, fields []string) []byte {
	var b bytes.Buffer
	for _, part := range append([]string{label}, fields...) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(part)))
		b.WriteString(part)
	}
	return b.Bytes()
}
