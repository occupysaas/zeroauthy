package hostedlogin

import (
	"errors"
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

var errHTML = errors.New("unsafe hosted template HTML")

func validateHTML(source string, partial bool) error {
	z := html.NewTokenizer(strings.NewReader(source))
	stack := []string{}
	inStyle := false
	var css strings.Builder
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return errHTML
		}
		t := z.Token()
		tag := strings.ToLower(t.Data)
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			if !allowedElement(tag, partial) {
				return errHTML
			}
			if partial && tag == "button" {
				return errHTML
			}
			switch tag {
			case "script", "iframe", "object", "embed", "base", "form", "meta", "link", "svg", "math":
				return errHTML
			}
			if tag == "style" {
				inStyle = true
				css.Reset()
			}
			if tag == "input" || tag == "select" || tag == "textarea" {
				if !partial {
					return errHTML
				}
				name, count, kind := "", 0, "text"
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "name") {
						name = a.Val
						count++
					}
					if strings.EqualFold(a.Key, "type") {
						kind = strings.ToLower(a.Val)
					}
				}
				if count != 1 || len(name) < 5 || len(name) > 128 || !strings.HasPrefix(name, "ulp-") {
					return errHTML
				}
				for _, r := range name[4:] {
					if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
						return errHTML
					}
				}
				if tag == "input" {
					switch kind {
					case "text", "email", "tel", "number", "checkbox", "radio":
					default:
						return errHTML
					}
				}
			}
			for _, a := range t.Attr {
				k := strings.ToLower(a.Key)
				if k == "id" {
					switch a.Val {
					case "state", "csrf", "username", "password", "email", "connection", "redirect_uri", "ticket", "hosted_revision":
						return errHTML
					}
				}
				if strings.HasPrefix(k, "on") || k == "style" || k == "formaction" || k == "srcdoc" || k == "hidden" || k == "inert" || k == "aria-hidden" || k == "form" || k == "autofocus" || k == "contenteditable" {
					return errHTML
				}
				if k == "href" || k == "src" {
					u, e := url.Parse(a.Val)
					if e != nil {
						return errHTML
					}
					if u.IsAbs() && (u.Scheme != "https" || u.User != nil) {
						return errHTML
					}
					if !u.IsAbs() && strings.HasPrefix(a.Val, "//") {
						return errHTML
					}
				}
			}
			// HTML ignores self-closing syntax on non-void elements. Such
			// fragments can consume or disable the following trusted widget.
			if tt == html.SelfClosingTagToken && !voidElement(tag) {
				return errHTML
			}
			if !voidElement(tag) {
				stack = append(stack, tag)
				if len(stack) > 32 {
					return errHTML
				}
			}
		}
		if tt == html.TextToken && inStyle {
			css.WriteString(t.Data)
		}
		if tt == html.EndTagToken {
			if len(stack) == 0 || stack[len(stack)-1] != tag {
				return errHTML
			}
			if tag == "style" {
				if err := ValidateCSS(css.String()); err != nil {
					return err
				}
				inStyle = false
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 || inStyle {
		return errHTML
	}
	return nil
}

func allowedElement(tag string, partial bool) bool {
	if partial {
		switch tag {
		case "html", "head", "body", "title":
			return false
		}
	}
	switch tag {
	case "html", "head", "body", "title", "style", "div", "main", "section", "article", "aside", "header", "footer", "nav", "p", "span", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "dl", "dt", "dd", "a", "img", "br", "hr", "strong", "em", "b", "i", "small", "blockquote", "code", "pre":
		return true
	case "label", "input", "select", "option", "textarea", "fieldset", "legend":
		return partial
	}
	return false
}

func validateTagPositions(source string) error {
	z := html.NewTokenizer(strings.NewReader(source))
	type frame struct {
		tag        string
		decoration bool
	}
	stack := []frame{}
	for {
		typeOf := z.Next()
		if typeOf == html.ErrorToken {
			if z.Err() == io.EOF {
				return nil
			}
			return errHTML
		}
		if typeOf != html.TextToken && (strings.Contains(string(z.Raw()), headMarker) || strings.Contains(string(z.Raw()), widgetMarker)) {
			return errHTML
		}
		token := z.Token()
		switch typeOf {
		case html.StartTagToken:
			if !voidElement(strings.ToLower(token.Data)) {
				f := frame{tag: strings.ToLower(token.Data)}
				for _, a := range token.Attr {
					if strings.EqualFold(a.Key, "class") {
						for _, class := range strings.Fields(a.Val) {
							if class == "za-decoration" {
								f.decoration = true
							}
						}
					}
				}
				stack = append(stack, f)
			}
		case html.EndTagToken:
			if len(stack) == 0 || stack[len(stack)-1].tag != strings.ToLower(token.Data) {
				return errHTML
			}
			stack = stack[:len(stack)-1]
		case html.TextToken:
			inHead, inBody, inDecoration := false, false, false
			validWidgetParent := true
			for _, f := range stack {
				inHead = inHead || f.tag == "head"
				inBody = inBody || f.tag == "body"
				inDecoration = inDecoration || f.tag == "style" || f.decoration
				switch f.tag {
				case "html", "body", "div", "main", "section", "article":
				default:
					validWidgetParent = false
				}
			}
			if strings.Contains(token.Data, headMarker) && (!inHead || inBody || inDecoration) {
				return errHTML
			}
			if strings.Contains(token.Data, widgetMarker) && (!inBody || inHead || inDecoration || !validWidgetParent) {
				return errHTML
			}
		}
	}
}

// Interpolation inside markup must remain inside a quoted attribute value.
// Liquid expressions are skipped as whole tokens so comparisons cannot alter
// the HTML scanner's state; structural parsing validates the resulting tags.
func validateInterpolationContexts(source string) error {
	inTag := false
	var quote byte
	for i := 0; i < len(source); i++ {
		if strings.HasPrefix(source[i:], "{{") || strings.HasPrefix(source[i:], "{%") {
			output := source[i+1] == '{'
			end := "%}"
			if output {
				end = "}}"
			}
			n := strings.Index(source[i+2:], end)
			if n < 0 {
				return errHTML
			}
			if inTag && (!output || quote == 0) {
				return errHTML
			}
			i += 2 + n + len(end) - 1
			continue
		}
		b := source[i]
		if inTag {
			if quote != 0 {
				if b == quote {
					quote = 0
				}
				continue
			}
			if b == '\'' || b == '"' {
				quote = b
				continue
			}
			if b == '>' {
				inTag = false
			}
		} else if b == '<' {
			inTag = true
		}
	}
	return nil
}

func voidElement(tag string) bool {
	switch tag {
	case "area", "br", "col", "hr", "img", "input", "source", "wbr":
		return true
	}
	return false
}
