// Package selfservice is the hosted self-service SSO assistant (Plan 37c
// Phase B, D-0150): a customer administrator holding an SSO ticket
// configures the one enterprise connection the ticket names.
package selfservice

import (
	"html/template"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Profile custom text may hold "basic styling tags and hyperlinks"
// (Auth0's OpenAPI). sanitize keeps only these elements, hyperlinks only
// with an https or mailto href, and no other attribute; everything else is
// emitted as escaped text.
var allowedTags = map[atom.Atom]bool{atom.B: true, atom.Strong: true, atom.I: true, atom.Em: true, atom.U: true, atom.Br: true, atom.P: true, atom.A: true, atom.Span: true}

const maxSanitizeBytes = 4096

func safeHref(v string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || (u.Scheme != "https" && u.Scheme != "mailto") || (u.Scheme == "https" && u.Host == "") {
		return "", false
	}
	return u.String(), true
}

// sanitize returns s as safe HTML.
func sanitize(s string) template.HTML {
	if len(s) > maxSanitizeBytes {
		s = s[:maxSanitizeBytes]
	}
	var b strings.Builder
	z := html.NewTokenizer(strings.NewReader(s))
	var open []atom.Atom
	for {
		switch z.Next() {
		case html.ErrorToken:
			for i := len(open) - 1; i >= 0; i-- {
				b.WriteString("</" + open[i].String() + ">")
			}
			return template.HTML(b.String()) // #nosec G203 -- built only from allowlisted tags and escaped text
		case html.TextToken:
			b.WriteString(html.EscapeString(string(z.Text())))
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if !allowedTags[t.DataAtom] {
				continue
			}
			if t.DataAtom == atom.Br {
				b.WriteString("<br>")
				continue
			}
			if t.DataAtom == atom.A {
				href := ""
				for _, a := range t.Attr {
					if a.Key == "href" && a.Namespace == "" {
						if v, ok := safeHref(a.Val); ok {
							href = v
						}
					}
				}
				if href == "" {
					continue
				}
				b.WriteString(`<a href="` + html.EscapeString(href) + `" rel="noopener noreferrer" target="_blank">`)
			} else {
				b.WriteString("<" + t.DataAtom.String() + ">")
			}
			open = append(open, t.DataAtom)
		case html.EndTagToken:
			t := z.Token()
			// Close only the innermost matching open element.
			for i := len(open) - 1; i >= 0; i-- {
				if open[i] == t.DataAtom {
					for j := len(open) - 1; j >= i; j-- {
						b.WriteString("</" + open[j].String() + ">")
					}
					open = open[:i]
					break
				}
			}
		}
	}
}
