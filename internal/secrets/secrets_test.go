package secrets

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	ok, err := Verify(h, "s3cret")
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v", ok, err)
	}
	ok, err = Verify(h, "wrong")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
	h2, _ := Hash("s3cret")
	if h == h2 {
		t.Fatal("two hashes of the same secret are identical; salt not random")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, enc := range []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=x,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaA",
	} {
		if _, err := Verify(enc, "x"); err == nil {
			t.Errorf("Verify(%q) returned no error", enc)
		}
	}
}

func TestRandomString(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		s := RandomString(32)
		if len(s) != 32 {
			t.Fatalf("len = %d", len(s))
		}
		for _, r := range s {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("unexpected rune %q in %q", r, s)
			}
		}
		if seen[s] {
			t.Fatalf("duplicate %q", s)
		}
		seen[s] = true
	}
}
