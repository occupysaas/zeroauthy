package selfservice

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"Hello":                                            "Hello",
		"<b>bold</b> and <em>em</em>":                      "<b>bold</b> and <em>em</em>",
		`<script>alert(1)</script>`:                        "alert(1)",
		`<img src=x onerror=alert(1)>`:                     "",
		`<a href="https://docs.example.test/sso">docs</a>`: `<a href="https://docs.example.test/sso" rel="noopener noreferrer" target="_blank">docs</a>`,
		`<a href="javascript:alert(1)">x</a>`:              "x",
		`<a href="//evil.test">x</a>`:                      "x",
		`<b onclick="x()" style="color:red">t</b>`:         "<b>t</b>",
		`<p>unclosed <i>i`:                                 "<p>unclosed <i>i</i></p>",
		`a &lt; b & "c"`:                                   "a &lt; b &amp; &#34;c&#34;",
		`<b><i>x</b>`:                                      "<b><i>x</i></b>",
		`<svg><a href="https://x.test">s</a></svg>`:        `<a href="https://x.test" rel="noopener noreferrer" target="_blank">s</a>`,
	} {
		if got := string(sanitize(in)); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// FuzzSanitize: the output contains no element or attribute outside the
// allowlist, whatever the input.
func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"<b>x</b>", `<a href="https://a.test" onclick=x>y</a>`, "<script>x</script>", "<p><b>", `<a href=javascript:x>`, "\x00<b>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := string(sanitize(s))
		z := html.NewTokenizer(strings.NewReader(out))
		for {
			tt := z.Next()
			if tt == html.ErrorToken {
				return
			}
			if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
				continue
			}
			tok := z.Token()
			if !allowedTags[tok.DataAtom] {
				t.Fatalf("element %q in %q from %q", tok.Data, out, s)
			}
			for _, a := range tok.Attr {
				ok := tok.DataAtom.String() == "a" && (a.Key == "rel" || a.Key == "target" || a.Key == "href" && (strings.HasPrefix(a.Val, "https://") || strings.HasPrefix(a.Val, "mailto:")))
				if !ok {
					t.Fatalf("attribute %s=%q in %q from %q", a.Key, a.Val, out, s)
				}
			}
		}
	})
}
