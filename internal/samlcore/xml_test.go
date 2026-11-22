package samlcore

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseRefusesDTDAndEntities(t *testing.T) {
	for name, doc := range map[string]string{
		"xxe":           `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		"billion laughs": `<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><l>&b;</l>`,
		"bare doctype":  `<!DOCTYPE r><r/>`,
		"undefined entity": `<r>&nope;</r>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseLimits(t *testing.T) {
	big := []byte("<r>" + strings.Repeat("a", MaxInputBytes) + "</r>")
	if _, err := Parse(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
	nest := func(n int) []byte {
		return []byte(strings.Repeat("<a>", n) + strings.Repeat("</a>", n))
	}
	if _, err := Parse(nest(MaxDepth)); err != nil {
		t.Fatalf("depth %d refused: %v", MaxDepth, err)
	}
	if _, err := Parse(nest(MaxDepth + 1)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("depth %d: %v", MaxDepth+1, err)
	}
}

func TestParseRefusesMalformedShapes(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":          ``,
		"two roots":      `<a/><b/>`,
		"trailing text":  `<a/>junk`,
		"processing ins": `<a><?evil x?></a>`,
		"invalid utf8":   "<a>\xff</a>",
		"unclosed":       `<a>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// An XML declaration and surrounding whitespace are fine.
	if _, err := Parse([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a/>\n")); err != nil {
		t.Fatal(err)
	}
}

// Vectors from Exclusive XML Canonicalization 1.0 §2.2 and Canonical XML
// 1.0 §3 (attribute order, empty elements, character references).
func TestExcC14NVectors(t *testing.T) {
	doc, err := Parse([]byte(`<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>`))
	if err != nil {
		t.Fatal(err)
	}
	elem2 := doc.Root().ChildElements()[0]
	got, err := Canonicalize(elem2, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>`
	if string(got) != want {
		t.Fatalf("exc-c14n\n got %s\nwant %s", got, want)
	}

	doc, err = Parse([]byte(`<e b="2" a="1" xmlns:z="urn:z" z:c="3"><!-- note --><f/>x&#38;y</e>`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ = Canonicalize(doc.Root(), false)
	if string(got) != `<e xmlns:z="urn:z" a="1" b="2" z:c="3"><f></f>x&amp;y</e>` {
		t.Fatalf("attribute order / comments stripped: %s", got)
	}
	withComments, _ := Canonicalize(doc.Root(), true)
	if !bytes.Contains(withComments, []byte("<!-- note -->")) {
		t.Fatalf("comments kept: %s", withComments)
	}
}
