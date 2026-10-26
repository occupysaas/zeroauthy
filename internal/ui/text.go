package ui

import (
	"html"
	"html/template"
	"net/url"
	"regexp"
	"strings"
)

var markdownLink = regexp.MustCompile(`\[([^\]\r\n]+)\]\(([^()\s]+)\)`)

// renderText escapes all text and recognizes only inline HTTPS/mailto links.
// It supports no raw HTML, images, embedded content or general Markdown.
func renderText(text string) template.HTML {
	var out strings.Builder
	offset := 0
	for _, match := range markdownLink.FindAllStringSubmatchIndex(text, -1) {
		out.WriteString(html.EscapeString(text[offset:match[0]]))
		label, destination := text[match[2]:match[3]], text[match[4]:match[5]]
		u, err := url.Parse(destination)
		safe := err == nil && u.User == nil && ((u.Scheme == "https" && u.Host != "") || (u.Scheme == "mailto" && u.Opaque != "" && u.RawQuery == ""))
		if safe {
			out.WriteString(`<a href="` + html.EscapeString(destination) + `" rel="noreferrer">` + html.EscapeString(label) + `</a>`)
		} else {
			out.WriteString(html.EscapeString(text[match[0]:match[1]]))
		}
		offset = match[1]
	}
	out.WriteString(html.EscapeString(text[offset:]))
	return template.HTML(out.String())
}
