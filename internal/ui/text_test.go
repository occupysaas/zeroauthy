package ui

import (
	"strings"
	"testing"
)

func TestPromptMarkdownLinks(t *testing.T) {
	html := string(renderText(`<b>Hi</b> [Help](https://help.example.test/path?a=1&b=2) [Email](mailto:help@example.test)`))
	for _, want := range []string{"&lt;b&gt;Hi&lt;/b&gt;", `href="https://help.example.test/path?a=1&amp;b=2"`, `href="mailto:help@example.test"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in %s", want, html)
		}
	}
	for _, source := range []string{`[Bad](javascript:alert)`, `[Bad](data:text/html,x)`, `[Bad](//evil.test)`} {
		if strings.Contains(string(renderText(source)), "<a ") {
			t.Errorf("executable link accepted: %s", source)
		}
	}
}
