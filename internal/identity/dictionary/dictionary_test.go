package dictionary

import "testing"

func TestEmbeddedLists(t *testing.T) {
	for _, tc := range []struct {
		list, word string
		want       bool
	}{
		{"en_10k", "password", true},
		{"en_10k", "PASSWORD", true},
		{"en_10k", "Qwerty", true},
		{"en_10k", "zq7!vK2#mR9x-unlikely", false},
		{"en_100k", "password", true},
		{"en_100k", "zq7!vK2#mR9x-unlikely", false},
		{"unknown", "password", false},
		{"", "password", false},
	} {
		if got := InDefault(tc.list, tc.word); got != tc.want {
			t.Errorf("InDefault(%q, %q) = %v, want %v", tc.list, tc.word, got, tc.want)
		}
	}
	if Size("en_100k") <= Size("en_10k") || Size("en_10k") < 9000 {
		t.Errorf("sizes: 10k=%d 100k=%d", Size("en_10k"), Size("en_100k"))
	}
}

func TestFold(t *testing.T) {
	// Unicode case folding, and composed against decomposed accents.
	if Fold("STRASSE") != Fold("Straße") {
		t.Error("ß does not fold to ss")
	}
	if Fold("Éclair") != Fold("éclair") {
		t.Error("composed and decomposed é differ")
	}
	if Fold("ΣΑΣ") != Fold("σας") {
		t.Error("sigma forms differ")
	}
}
