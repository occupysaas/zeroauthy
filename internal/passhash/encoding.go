package passhash

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

// encodePassword converts the password the way Node's Buffer.from(s, enc)
// does, because Auth0's documented encodings are Node's. ascii, latin1 and
// binary keep the low 8 bits of each UTF-16 code unit (never an error);
// utf16le and ucs2 write UTF-16LE code units.
func encodePassword(s, enc string) []byte {
	switch enc {
	case "ascii", "latin1", "binary":
		units := utf16.Encode([]rune(s))
		out := make([]byte, len(units))
		for i, u := range units {
			out[i] = byte(u)
		}
		return out
	case "utf16le", "ucs2":
		units := utf16.Encode([]rune(s))
		out := make([]byte, 0, 2*len(units))
		for _, u := range units {
			out = append(out, byte(u), byte(u>>8))
		}
		return out
	}
	return []byte(s)
}

// decodeValue decodes a hash, salt or key value in its declared encoding.
// base64 accepts the standard and URL alphabets, with or without padding, as
// Node does.
func decodeValue(v, enc string) ([]byte, error) {
	switch enc {
	case "hex":
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%w: hex: %v", ErrUnusable, err)
		}
		return b, nil
	case "base64":
		return decodeBase64(v)
	case "utf8", "":
		return []byte(v), nil
	}
	return nil, fmt.Errorf("%w: encoding %q", ErrUnusable, enc)
}

func decodeBase64(v string) ([]byte, error) {
	v = strings.TrimRight(v, "=")
	v = strings.NewReplacer("-", "+", "_", "/").Replace(v)
	b, err := base64.RawStdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %v", ErrUnusable, err)
	}
	return b, nil
}

// saltedInput joins salt and password in the salt's position (prefix is the
// default). Without a salt it is the password.
func (s *Spec) saltedInput(pw []byte) ([]byte, error) {
	if s.Salt == nil {
		return pw, nil
	}
	salt, err := decodeValue(s.Salt.Value, s.Salt.Encoding)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(salt)+len(pw))
	if s.Salt.Position == "suffix" {
		out = append(out, pw...)
		return append(out, salt...), nil
	}
	out = append(out, salt...)
	return append(out, pw...), nil
}
