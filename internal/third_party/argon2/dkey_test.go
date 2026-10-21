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
