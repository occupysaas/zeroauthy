package httpx

import "testing"

func TestIPBucket(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.7":                   "198.51.100.7",
		"::ffff:198.51.100.7":            "198.51.100.7",
		"2001:db8:1:2:aaaa:bbbb:cccc:dd": "2001:db8:1:2::/64",
		"2001:db8:1:2::1":                "2001:db8:1:2::/64",
		"2001:DB8:1:3::1":                "2001:db8:1:3::/64",
		"fe80::1%eth0":                   "fe80::/64",
		"::1":                            "::/64",
		"not-an-ip":                      "not-an-ip",
		"":                               "",
	} {
		if got := IPBucket(in); got != want {
			t.Errorf("IPBucket(%q) = %q, want %q", in, got, want)
		}
	}
}
