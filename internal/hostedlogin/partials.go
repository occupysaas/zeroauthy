package hostedlogin

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// ValidatePartials applies the form field policy to a prompt's screen/slot map.
func ValidatePartials(screens map[string]map[string]string) error {
	fields := map[string]bool{}
	for _, slots := range screens {
		for slot, source := range slots {
			if err := ValidateSource(source, true); err != nil {
				return err
			}
			z := html.NewTokenizer(strings.NewReader(source))
			for {
				tt := z.Next()
				if tt == html.ErrorToken {
					if z.Err() == io.EOF {
						break
					}
					return ErrTemplate
				}
				if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
					continue
				}
				t := z.Token()
				tag := strings.ToLower(t.Data)
				if tag != "input" && tag != "select" && tag != "textarea" {
					continue
				}
				if slot != "form-content-start" && slot != "form-content-end" {
					return ErrTemplate
				}
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "name") {
						if fields[a.Val] || len(fields) >= 30 {
							return ErrTemplate
						}
						fields[a.Val] = true
					}
				}
			}
		}
	}
	return nil
}
