package webauthn

import (
	"encoding/binary"

	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Authenticator data flags (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	aaguid    [16]byte
	credID    []byte
	cose      []byte
}

func (a *authData) up() bool { return a.flags&flagUP != 0 }
func (a *authData) uv() bool { return a.flags&flagUV != 0 }
func (a *authData) be() bool { return a.flags&flagBE != 0 }
func (a *authData) bs() bool { return a.flags&flagBS != 0 }

// parseAuthData parses authenticator data exactly: attested credential data
// when AT is set, bounded-CBOR extensions when ED is set, no unparsed tail.
func parseAuthData(b []byte) (*authData, error) {
	if len(b) < 37 {
		return nil, fail("parse", "authenticator data shorter than 37 bytes")
	}
	a := &authData{rpIDHash: b[:32], flags: b[32], signCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if a.flags&flagAT != 0 {
		if len(rest) < 18 {
			return nil, fail("parse", "attested credential data truncated")
		}
		copy(a.aaguid[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n > webauthnrules.Limits.CredentialIDMax {
			return nil, fail("too_large", "credential ID over %d bytes", webauthnrules.Limits.CredentialIDMax)
		}
		if n == 0 || n > len(rest) {
			return nil, fail("parse", "credential ID truncated")
		}
		a.credID, rest = rest[:n], rest[n:]
		_, after, err := DecodeCBORPrefix(rest)
		if err != nil {
			return nil, fail("parse", "credential public key is not CBOR")
		}
		a.cose, rest = rest[:len(rest)-len(after)], after
	}
	if a.flags&flagED != 0 {
		_, after, err := DecodeCBORPrefix(rest)
		if err != nil {
			return nil, fail("parse", "extensions are not CBOR")
		}
		rest = after
	}
	if len(rest) != 0 {
		return nil, fail("parse", "%d unparsed bytes in authenticator data", len(rest))
	}
	return a, nil
}
