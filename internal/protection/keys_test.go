package protection

import "testing"

func TestProtectionIPIdentity(t *testing.T) {
	a := LoginKey("t", "c", " Alice@Example.test ", "::ffff:192.0.2.1", "count_per_identifier_and_ip")
	b := LoginKey("t", "c", "alice@example.test", "192.0.2.1", "count_per_identifier_and_ip")
	if a != b {
		t.Fatalf("different identity: %#v %#v", a, b)
	}
	if CanonicalIP("bad") != "unknown" || CanonicalIP("also bad") != "unknown" {
		t.Fatal("invalid addresses must share non-IP key")
	}
	if LoginKey("t", "c", "a", "192.0.2.1", "count_per_identifier").IP != "" {
		t.Fatal("identifier mode includes IP")
	}
}
