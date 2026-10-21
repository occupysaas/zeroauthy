package passhash

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Whirlpool test strings from ISO/IEC 10118-3 / the NESSIE test vectors; the
// digests are cross-checked against `openssl dgst -whirlpool` by the vector
// generator.
func TestWhirlpoolPublishedVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"},
		{"a", "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a"},
		{"abc", "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"},
		{"message digest", "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e"},
		{strings.Repeat("a", 1000000), "0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01"},
	}
	for _, c := range cases {
		h := newWhirlpool()
		h.Write([]byte(c.in))
		if got := hex.EncodeToString(h.Sum(nil)); got != c.want {
			t.Errorf("whirlpool(%.20q len %d) = %s, want %s", c.in, len(c.in), got, c.want)
		}
	}
}

func TestWhirlpoolIncrementalAndSumKeepsState(t *testing.T) {
	msg := []byte(strings.Repeat("0123456789", 37))
	whole := newWhirlpool()
	whole.Write(msg)
	want := whole.Sum(nil)

	parts := newWhirlpool()
	for i := 0; i < len(msg); i += 7 {
		end := min(i+7, len(msg))
		parts.Write(msg[i:end])
		parts.Sum(nil) // must not disturb the state
	}
	if hex.EncodeToString(parts.Sum(nil)) != hex.EncodeToString(want) {
		t.Fatal("incremental write differs")
	}
	parts.Reset()
	parts.Write(msg)
	if hex.EncodeToString(parts.Sum(nil)) != hex.EncodeToString(want) {
		t.Fatal("reset differs")
	}
}

// Digests computed with `openssl dgst -provider legacy -provider default -mdc2`.
func TestMDC2MatchesOpenSSL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "52525252525252522525252525252525"},
		{"a", "04f59c1ce01b9b54d329c2baae4f6c9f"},
		{"abc", "3ff42120ee863f5d910cf2ee5064f82f"},
		{"message digest", "fa13444f04050d012f209890b1c235ab"},
		{"12345678", "e5d00157a07c89b76b7fd9d1e834e4aa"},
		{"123456789", "6625851c059ff01fd2012fe255f2da8a"},
		{"1234567890123456", "17e8386ce91ee44981a6336647d4aac7"},
	}
	for _, c := range cases {
		h := newMDC2()
		h.Write([]byte(c.in))
		if got := hex.EncodeToString(h.Sum(nil)); got != c.want {
			t.Errorf("mdc2(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
