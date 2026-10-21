package secrets

import (
	"bytes"
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

func TestVerifyRejectsOutOfRangeParameters(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2FsdA"                     // 16 bytes, raw std base64
	key := "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // 32 bytes
	for _, params := range []string{
		"m=0,t=2,p=1",          // memory below 8*p
		"m=19456,t=0,p=1",      // zero time cost
		"m=19456,t=2,p=0",      // zero parallelism
		"m=4294967295,t=2,p=1", // absurd memory
		"m=19456,t=99,p=1",     // absurd time cost
	} {
		enc := "$argon2id$v=19$" + params + "$" + salt + "$" + key
		if _, err := Verify(enc, "x"); err == nil {
			t.Errorf("Verify accepted %s", params)
		}
	}
	short := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$" + key // 4-byte salt
	if _, err := Verify(short, "x"); err == nil {
		t.Error("Verify accepted a 4-byte salt")
	}
}

func TestHashToken(t *testing.T) {
	// SHA-256("abc"), FIPS 180-2 test vector.
	if got, want := HashToken("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("HashToken = %s", got)
	}
}

func TestRandomHex(t *testing.T) {
	a, b := RandomHex(12), RandomHex(12)
	if len(a) != 24 || a == b || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("RandomHex = %q, %q", a, b)
	}
}

func TestDeriveKey(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveKey(master, "purpose a")
	if err != nil || len(a) != 32 {
		t.Fatalf("DeriveKey = %x, %v", a, err)
	}
	again, _ := DeriveKey(master, "purpose a")
	b, _ := DeriveKey(master, "purpose b")
	other, _ := DeriveKey(bytes.Repeat([]byte{8}, 32), "purpose a")
	if !bytes.Equal(a, again) || bytes.Equal(a, b) || bytes.Equal(a, other) || bytes.Equal(a, master) {
		t.Error("a derived key must be stable, and differ by purpose and by master key")
	}
}
