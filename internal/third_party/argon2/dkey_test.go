package argon2

import (
	"encoding/base64"
	"testing"
)

// Reference value from the argon2 command line tool (reference C
// implementation):
//
//	printf 'Pa55w0rd!' | argon2 somesaltsomesalt -d -t 2 -k 64 -p 1 -l 32 -e
//	$argon2d$v=19$m=64,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$9qwlKLp0tLmScb4/tn+NCeKxQLelOcf5JuS7IlpfnIU
func TestDKeyMatchesReferenceCLI(t *testing.T) {
	want, err := base64.RawStdEncoding.DecodeString("9qwlKLp0tLmScb4/tn+NCeKxQLelOcf5JuS7IlpfnIU")
	if err != nil {
		t.Fatal(err)
	}
	got := DKey([]byte("Pa55w0rd!"), []byte("somesaltsomesalt"), 2, 64, 1, 32)
	if string(got) != string(want) {
		t.Fatalf("DKey = %x, want %x", got, want)
	}
	if id := IDKey([]byte("Pa55w0rd!"), []byte("somesaltsomesalt"), 2, 64, 1, 32); string(id) == string(got) {
		t.Fatal("DKey and IDKey agree")
	}
}

// Argon2 1.0 against the argon2 CLI (`-v 10`) is checked by the passhash vectors
// (argon2/*/v16/*); this tests the entry point.
func TestKeyVersion10(t *testing.T) {
	pw, salt := []byte("Pa55w0rd!"), []byte("oldversionsalt")
	v10 := KeyVersion("argon2id", Version10, pw, salt, 3, 256, 2, 32)
	v13 := KeyVersion("argon2id", Version, pw, salt, 3, 256, 2, 32)
	if string(v13) != string(IDKey(pw, salt, 3, 256, 2, 32)) {
		t.Fatal("KeyVersion(1.3) differs from IDKey")
	}
	if string(v10) == string(v13) {
		t.Fatal("1.0 and 1.3 agree")
	}
	if KeyVersion("argon2x", Version, pw, salt, 1, 8, 1, 4) != nil || KeyVersion("argon2i", 0x11, pw, salt, 1, 8, 1, 4) != nil {
		t.Fatal("unknown variant or version accepted")
	}
}
