// Package samlcore is zeroauthy's SAML 2.0 XML core (Plan 37a, D-0130): safe
// parsing, exclusive canonicalization, XML signatures, XML encryption and
// the SAML message and metadata builders. Every SAML document zeroauthy reads
// goes through Parse first.
package samlcore

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// Input limits (spec anti-goals: XXE / billion laughs).
const (
	MaxInputBytes = 256 << 10
	MaxDepth      = 50
)

// Parse errors. Messages never echo document content.
var (
	ErrTooLarge  = errors.New("samlcore: document exceeds 256 KiB")
	ErrTooDeep   = errors.New("samlcore: document nesting exceeds 50 levels")
	ErrDTD       = errors.New("samlcore: DTDs and entity declarations are refused")
	ErrMalformed = errors.New("samlcore: malformed XML document")
)

// Parse reads one XML document after a token-level pre-scan that refuses DTDs,
// processing instructions other than the XML declaration, undefined
// entities, invalid UTF-8, excess depth, more than one root element and
// trailing content. Only then is the tree built.
func Parse(raw []byte) (*etree.Document, error) {
	if len(raw) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	if !utf8.Valid(raw) {
		return nil, ErrMalformed
	}
	if err := prescan(raw); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.ReadSettings = etree.ReadSettings{Permissive: false}
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, ErrMalformed
	}
	if doc.Root() == nil {
		return nil, ErrMalformed
	}
	return doc, nil
}

func prescan(raw []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	dec.Entity = nil // only the five predefined entities
	depth, roots, first := 0, 0, true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ErrMalformed
		}
		switch t := tok.(type) {
		case xml.Directive:
			return ErrDTD
		case xml.ProcInst:
			if !first || t.Target != "xml" {
				return ErrMalformed
			}
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return ErrMalformed
				}
			}
			depth++
			if depth > MaxDepth {
				return ErrTooDeep
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return ErrMalformed
			}
		}
		first = false
	}
	if roots != 1 || depth != 0 {
		return ErrMalformed
	}
	return nil
}

// errorf wraps internal failures without document content.
func errorf(format string, args ...any) error { return fmt.Errorf("samlcore: "+format, args...) }
