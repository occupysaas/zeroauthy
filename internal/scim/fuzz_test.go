package scim

import "testing"

// FuzzParseFilter feeds arbitrary SCIM filters (untrusted query input) to
// the parser: it must never panic, and an accepted filter must reparse to
// the same canonical form.
func FuzzParseFilter(f *testing.F) {
	for _, seed := range []string{`userName eq "jdoe"`, `(a eq 1 or b eq true) and c eq null`, `emails[type eq "work"].value eq "x"`,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "R&D"`, `members[value eq "u1"]`, `((((a eq "b"))))`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParsePath(s)
		flt, err := ParseFilter(s)
		if err != nil {
			return
		}
		if len(flt.String()) > maxFilterBytes {
			return // escaping can lengthen the canonical form past the input limit
		}
		again, err := ParseFilter(flt.String())
		if err != nil || again.String() != flt.String() {
			t.Fatalf("canonical form does not reparse: %q -> %q (%v)", s, flt.String(), err)
		}
	})
}
