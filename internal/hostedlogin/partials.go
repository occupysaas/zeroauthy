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
		sources := []string{}
		for slot, source := range slots {
			sources = append(sources, source)
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
		if !controlsLabeled(sources) {
			return ErrTemplate
		}
	}
	return nil
}

func controlsLabeled(sources []string) bool {
	doc, err := html.Parse(strings.NewReader(strings.Join(sources, "\n")))
	if err != nil {
		return false
	}
	ids, labels := map[string]bool{}, map[string]bool{}
	controls := []*html.Node{}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				if a.Key == "id" {
					ids[a.Val] = true
				}
				if n.Data == "label" && a.Key == "for" {
					labels[a.Val] = true
				}
			}
			switch n.Data {
			case "input", "select", "textarea":
				controls = append(controls, n)
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	for _, control := range controls {
		id, label, by := "", "", ""
		for _, a := range control.Attr {
			switch a.Key {
			case "id":
				id = a.Val
			case "aria-label":
				label = strings.TrimSpace(a.Val)
			case "aria-labelledby":
				by = a.Val
			}
		}
		if label != "" || (id != "" && labels[id]) {
			continue
		}
		wrapped := false
		for p := control.Parent; p != nil; p = p.Parent {
			if p.Type == html.ElementNode && p.Data == "label" {
				wrapped = true
				break
			}
		}
		if wrapped {
			continue
		}
		references := strings.Fields(by)
		valid := len(references) > 0
		for _, ref := range references {
			valid = valid && ids[ref] && ref != id
		}
		if !valid {
			return false
		}
	}
	return true
}
