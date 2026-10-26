package hostedlogin

import (
	"context"
	"errors"
	"html"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/liquid"
	xhtml "golang.org/x/net/html"
)

var ErrPartialFields = errors.New("invalid additional form fields")

type PartialOutput struct {
	Slots        map[string]string
	Fields       map[string]string
	AssetOrigins []string
}

func RenderPartials(parent context.Context, slots map[string]string, variables map[string]any, captured map[string]string, nonce string) (PartialOutput, error) {
	if err := ValidatePartials(map[string]map[string]string{"screen": slots}); err != nil {
		return PartialOutput{}, err
	}
	ctx, cancel := context.WithTimeout(parent, 100*time.Millisecond)
	defer cancel()
	out := PartialOutput{Slots: map[string]string{}, Fields: map[string]string{}}
	vars := ProjectContext(variables)
	total := 0
	for _, slot := range []string{"form-content-start", "form-content-end", "form-footer-start", "form-footer-end"} {
		source := slots[slot]
		if source == "" {
			continue
		}
		if len(source) > 40<<10 || utf8.RuneCountInString(source) > 10000 {
			return PartialOutput{}, ErrTemplate
		}
		if err := ValidateSource(source, true); err != nil {
			return PartialOutput{}, err
		}
		rendered, err := liquid.Render(ctx, source, vars, nil, liquid.Limits{MaxSourceBytes: 40 << 10, MaxOutputBytes: 512 << 10, EscapeVariables: true})
		if err != nil {
			return PartialOutput{}, err
		}
		if err := validateHTML(rendered, true); err != nil {
			return PartialOutput{}, err
		}
		z := xhtml.NewTokenizer(strings.NewReader(rendered))
		var buf strings.Builder
		textarea, selectName := "", ""
		for {
			tt := z.Next()
			if tt == xhtml.ErrorToken {
				if z.Err() == io.EOF {
					break
				}
				return PartialOutput{}, errHTML
			}
			raw := string(z.Raw())
			token := z.Token()
			if textarea != "" {
				if tt == xhtml.EndTagToken && token.Data == "textarea" {
					buf.WriteString(html.EscapeString(captured[textarea]))
					buf.WriteString(raw)
					textarea = ""
				}
				continue
			}
			if tt == xhtml.EndTagToken && token.Data == "select" {
				selectName = ""
			}
			if tt != xhtml.StartTagToken && tt != xhtml.SelfClosingTagToken {
				buf.WriteString(raw)
				continue
			}
			switch token.Data {
			case "img":
				if origin := AssetOrigin(attr(token, "src")); origin != "" && !slices.Contains(out.AssetOrigins, origin) {
					out.AssetOrigins = append(out.AssetOrigins, origin)
				}
			case "style":
				setAttr(&token, "nonce", nonce)
			case "input", "select", "textarea":
				if slot != "form-content-start" && slot != "form-content-end" {
					return PartialOutput{}, ErrPartialFields
				}
				name := attr(token, "name")
				kind := attr(token, "type")
				if kind == "" {
					kind = "text"
				}
				if token.Data != "input" {
					kind = token.Data
				}
				if _, exists := out.Fields[name]; exists || len(out.Fields) >= 30 {
					return PartialOutput{}, ErrPartialFields
				}
				out.Fields[name] = kind
				if captured != nil {
					value := captured[name]
					switch token.Data {
					case "textarea":
						textarea = name
					case "select":
						selectName = name
					default:
						if kind == "checkbox" || kind == "radio" {
							removeAttr(&token, "checked")
							option := attr(token, "value")
							if option == "" {
								option = "on"
							}
							if value == option {
								setAttr(&token, "checked", "")
							}
						} else {
							setAttr(&token, "value", value)
						}
					}
				}
			case "option":
				if selectName != "" {
					removeAttr(&token, "selected")
					if attr(token, "value") == captured[selectName] {
						setAttr(&token, "selected", "")
					}
				}
			}
			buf.WriteString(token.String())
		}
		total += buf.Len()
		if total > 512<<10 {
			return PartialOutput{}, liquid.ErrLimit
		}
		out.Slots[slot] = buf.String()
	}
	sources := []string{}
	for _, source := range out.Slots {
		sources = append(sources, source)
	}
	if !controlsLabeled(sources) {
		return PartialOutput{}, ErrTemplate
	}
	return out, nil
}

func CaptureFields(form url.Values, fields map[string]string, current map[string]string) (map[string]string, error) {
	next := maps.Clone(current)
	if next == nil {
		next = map[string]string{}
	}
	for name := range fields {
		delete(next, name)
	}
	for name, values := range form {
		if !strings.HasPrefix(name, "ulp-") {
			continue
		}
		if _, ok := fields[name]; !ok || len(values) != 1 || len(name) > 128 || len(values[0]) > 1024 || !utf8.ValidString(values[0]) {
			return nil, ErrPartialFields
		}
		next[name] = values[0]
	}
	total := 0
	for name, value := range next {
		total += len(name) + len(value)
	}
	if len(next) > 30 || total > 8<<10 {
		return nil, ErrPartialFields
	}
	return next, nil
}

func attr(t xhtml.Token, key string) string {
	for _, a := range t.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
func removeAttr(t *xhtml.Token, key string) {
	attrs := t.Attr[:0]
	for _, a := range t.Attr {
		if a.Key != key {
			attrs = append(attrs, a)
		}
	}
	t.Attr = attrs
}
func setAttr(t *xhtml.Token, key, value string) {
	removeAttr(t, key)
	t.Attr = append(t.Attr, xhtml.Attribute{Key: key, Val: value})
}

// NonceStyles adds a response nonce to style elements in already validated
// renderer output. It never turns tenant-authored script into trusted content.
func NonceStyles(source, nonce string) string {
	z := xhtml.NewTokenizer(strings.NewReader(source))
	var out strings.Builder
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			break
		}
		raw := string(z.Raw())
		if tt == xhtml.StartTagToken {
			t := z.Token()
			if t.Data == "style" {
				setAttr(&t, "nonce", nonce)
				out.WriteString(t.String())
				continue
			}
		}
		out.WriteString(raw)
	}
	return out.String()
}
