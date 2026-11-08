package webauthn

import (
	"encoding/binary"
	"math"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// DecodeCBOR decodes the RFC 8949 subset WebAuthn needs: unsigned and
// negative integers, byte and text strings, arrays, maps (int64 or string
// keys, no duplicates) and false/true/null. Tags, floats, undefined,
// indefinite lengths and trailing bytes are refused. Every length is checked
// against the remaining input before anything is allocated.
func DecodeCBOR(b []byte, maxDepth, maxItems int) (any, error) {
	d := decoder{maxDepth: maxDepth, maxItems: maxItems}
	v, rest, err := d.item(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fail("parse", "%d trailing bytes", len(rest))
	}
	return v, nil
}

// DecodeCBORPrefix decodes one item and returns the bytes after it (used
// for authenticator data, where extensions follow the credential key).
func DecodeCBORPrefix(b []byte) (v any, rest []byte, err error) {
	d := decoder{maxDepth: webauthnrules.Limits.CBORDepth, maxItems: webauthnrules.Limits.CBORItems}
	return d.item(b, 0)
}

type decoder struct {
	maxDepth, maxItems, items int
}

func (d *decoder) count(n uint64) error {
	if n > uint64(d.maxItems) || d.items+int(n) > d.maxItems {
		return fail("parse", "more than %d items", d.maxItems)
	}
	d.items += int(n)
	return nil
}

func (d *decoder) item(b []byte, depth int) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, fail("parse", "unexpected end of input")
	}
	major, info := b[0]>>5, b[0]&31
	b = b[1:]
	if major == 7 {
		switch info {
		case 20:
			return false, b, nil
		case 21:
			return true, b, nil
		case 22:
			return nil, b, nil
		}
		return nil, nil, fail("parse", "unsupported simple value or float %d", info)
	}
	n, b, err := argument(info, b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0:
		if n > math.MaxInt64 {
			return nil, nil, fail("parse", "integer out of range")
		}
		return int64(n), b, nil
	case 1:
		if n > math.MaxInt64 {
			return nil, nil, fail("parse", "integer out of range")
		}
		return -1 - int64(n), b, nil
	case 2, 3:
		if n > uint64(len(b)) {
			return nil, nil, fail("parse", "string longer than input")
		}
		s := b[:n]
		if major == 3 {
			if !utf8.Valid(s) {
				return nil, nil, fail("parse", "invalid UTF-8 text")
			}
			return string(s), b[n:], nil
		}
		return append([]byte(nil), s...), b[n:], nil
	case 4, 5:
		if depth+1 > d.maxDepth {
			return nil, nil, fail("parse", "nesting deeper than %d", d.maxDepth)
		}
		per := uint64(1)
		if major == 5 {
			per = 2
		}
		// Each element takes at least one byte: refuse counts the input cannot hold.
		if n > uint64(len(b))/per {
			return nil, nil, fail("parse", "container longer than input")
		}
		if err := d.count(n); err != nil {
			return nil, nil, err
		}
		if major == 4 {
			out := make([]any, 0, n)
			for range n {
				var v any
				if v, b, err = d.item(b, depth+1); err != nil {
					return nil, nil, err
				}
				out = append(out, v)
			}
			return out, b, nil
		}
		out := make(map[any]any, n)
		for range n {
			var k, v any
			if k, b, err = d.item(b, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, fail("parse", "map key must be an integer or text")
			}
			if _, dup := out[k]; dup {
				return nil, nil, fail("parse", "duplicate map key")
			}
			if v, b, err = d.item(b, depth+1); err != nil {
				return nil, nil, err
			}
			out[k] = v
		}
		return out, b, nil
	}
	return nil, nil, fail("parse", "unsupported major type %d", major)
}

// argument reads the additional-information argument; indefinite lengths
// (31) and reserved values (28–30) are refused.
func argument(info byte, b []byte) (uint64, []byte, error) {
	switch {
	case info < 24:
		return uint64(info), b, nil
	case info == 24 && len(b) >= 1:
		return uint64(b[0]), b[1:], nil
	case info == 25 && len(b) >= 2:
		return uint64(binary.BigEndian.Uint16(b)), b[2:], nil
	case info == 26 && len(b) >= 4:
		return uint64(binary.BigEndian.Uint32(b)), b[4:], nil
	case info == 27 && len(b) >= 8:
		return binary.BigEndian.Uint64(b), b[8:], nil
	case info >= 28:
		return 0, nil, fail("parse", "indefinite or reserved length")
	}
	return 0, nil, fail("parse", "truncated argument")
}
