package loginid

import (
	"strings"
	"testing"
)

func TestRules(t *testing.T) {
	for _, c := range []struct {
		name string
		got  bool
		want bool
	}{
		{"email", ValidEmail("a@b.test"), true},
		{"email with name", ValidEmail("A <a@b.test>"), false},
		{"email too long", ValidEmail(strings.Repeat("a", 250) + "@b.test"), false},
		{"not an email", ValidEmail("not-an-email"), false},
		{"username", ValidUsername("alice_1.x+y-z"), true},
		{"username with @", ValidUsername("a@b"), false},
		{"username too long", ValidUsername(strings.Repeat("a", 65)), false},
		{"picture", ValidPicture("https://img.test/a.png"), true},
		{"picture http", ValidPicture("http://img.test/a.png"), false},
		{"picture too long", ValidPicture("https://img.test/" + strings.Repeat("a", MaxPictureLength)), false},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if Normalize("  Alice@Example.COM ") != "alice@example.com" {
		t.Error("Normalize")
	}
}
