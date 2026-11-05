package webauthn

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// head encodes a CBOR initial byte and argument (RFC 8949 §3).
func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}

// enc encodes test values: int/int64, string, []byte, []any, cmap (ordered pairs), bool, nil.
type cmap [][2]any

func enc(v any) []byte {
	switch x := v.(type) {
	case int:
		return enc(int64(x))
	case int64:
		if x >= 0 {
			return head(0, uint64(x))
		}
		return head(1, uint64(-1-x))
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case string:
		return append(head(3, uint64(len(x))), x...)
	case []any:
		out := head(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, enc(e)...)
		}
		return out
	case cmap:
		out := head(5, uint64(len(x)))
		for _, kv := range x {
			out = append(out, enc(kv[0])...)
			out = append(out, enc(kv[1])...)
		}
		return out
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case nil:
		return []byte{0xf6}
	}
	panic("enc: unsupported")
}

func TestCBORSubset(t *testing.T) {
	ok := []struct {
		in   []byte
		want any
	}{
		{enc(0), int64(0)},
		{enc(23), int64(23)},
		{enc(1 << 40), int64(1 << 40)},
		{enc(-1), int64(-1)},
		{enc(-500), int64(-500)},
		{enc([]byte{1, 2, 3}), []byte{1, 2, 3}},
		{enc("fmt"), "fmt"},
		{enc([]any{1, "a"}), []any{int64(1), "a"}},
		{enc(cmap{{1, 2}, {"k", []byte{9}}}), map[any]any{int64(1): int64(2), "k": []byte{9}}},
		{enc(false), false},
		{enc(true), true},
		{enc(nil), nil},
	}
	for _, c := range ok {
		got, err := DecodeCBOR(c.in, 16, 1024)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("DecodeCBOR(%x) = %#v, %v; want %#v", c.in, got, err, c.want)
		}
	}
	deep := enc(1)
	for range 17 {
		deep = append(head(4, 1), deep...)
	}
	many := head(4, 1025)
	for range 1025 {
		many = append(many, enc(0)...)
	}
	bad := map[string][]byte{
		"tag":                {0xc0, 0x00},
		"half float":         {0xf9, 0x3c, 0x00},
		"single float":       {0xfa, 0, 0, 0, 0},
		"double float":       {0xfb, 0, 0, 0, 0, 0, 0, 0, 0},
		"indefinite bytes":   {0x5f, 0x41, 0x00, 0xff},
		"indefinite array":   {0x9f, 0x00, 0xff},
		"undefined":          {0xf7},
		"duplicate map key":  enc(cmap{{1, 2}, {1, 3}}),
		"trailing bytes":     append(enc(1), 0x00),
		"truncated bytes":    {0x45, 1, 2},
		"array beyond input": {0x9a, 0xff, 0xff, 0xff, 0xff},
		"depth 17":           deep,
		"1025 items":         many,
		"empty":              {},
		"non-canonical key":  enc(cmap{{[]any{1}, 1}}),
	}
	for name, in := range bad {
		if _, err := DecodeCBOR(in, 16, 1024); err == nil || Reason(err) != "parse" {
			t.Errorf("%s: err %v reason %q, want parse", name, err, Reason(err))
		}
	}
}

func TestCBORPrefixLeavesRest(t *testing.T) {
	in := append(enc(cmap{{1, 2}}), 0xaa, 0xbb)
	v, rest, err := DecodeCBORPrefix(in)
	if err != nil || !reflect.DeepEqual(v, map[any]any{int64(1): int64(2)}) || !bytes.Equal(rest, []byte{0xaa, 0xbb}) {
		t.Fatalf("prefix = %#v %x %v", v, rest, err)
	}
}

func FuzzDecodeCBOR(f *testing.F) {
	for _, seed := range [][]byte{enc(cmap{{1, 2}, {"x", []any{1, "y", []byte{3}}}}), {0x9f}, {0xbf}, head(2, 1<<30)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeCBOR(b, 16, 1024)
		_, _, _ = DecodeCBORPrefix(b)
	})
}
