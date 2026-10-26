package hostedlogin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/liquid"
	xhtml "golang.org/x/net/html"
)

var ErrTemplate = errors.New("invalid hosted page template")

const headMarker = "ZA_INTERNAL_HEAD_MARKER"
const widgetMarker = "ZA_INTERNAL_WIDGET_MARKER"

type RenderInput struct {
	Source       string
	Variables    map[string]any
	Head, Widget string
	Partials     map[string]string
	Nonce        string
}
type RenderOutput struct {
	HTML         string
	AssetOrigins []string
}
type Renderer struct{}

func ValidateSource(source string, partial bool) error {
	if !utf8.ValidString(source) || len(source) > 100<<10 {
		return ErrTemplate
	}
	if strings.Contains(source, "<script") || strings.Contains(source, "javascript:") {
		return ErrTemplate
	}
	if strings.Contains(source, headMarker) || strings.Contains(source, widgetMarker) {
		return ErrTemplate
	}
	if err := validateInterpolationContexts(source); err != nil {
		return err
	}
	normalized := normalizeTags(source)
	if partial && (strings.Contains(normalized, headMarker) || strings.Contains(normalized, widgetMarker)) {
		return ErrTemplate
	}
	if !partial {
		if strings.Count(normalized, headMarker) != 1 || strings.Count(normalized, widgetMarker) < 1 {
			return ErrTemplate
		}
		if err := validateTagPositions(normalized); err != nil {
			return err
		}
	}
	if err := validateHTML(normalized, partial); err != nil {
		return err
	}
	if err := liquid.Validate(context.Background(), normalized, liquid.Limits{MaxSourceBytes: len(normalized), MaxOutputBytes: 512 << 10}); err != nil {
		return err
	}
	return nil
}

var trustedTag = regexp.MustCompile(`\{%-?\s*(auth0:head|auth0:widget)\s*-?%\}`)

func normalizeTags(s string) string {
	return trustedTag.ReplaceAllStringFunc(s, func(tag string) string {
		if strings.Contains(tag, "auth0:head") {
			return headMarker
		}
		return widgetMarker
	})
}
func (Renderer) Render(ctx context.Context, in RenderInput) (RenderOutput, error) {
	if err := ctx.Err(); err != nil {
		return RenderOutput{}, err
	}
	if err := ValidateSource(in.Source, false); err != nil {
		return RenderOutput{}, err
	}
	vars := ProjectContext(in.Variables)
	escapeContext(vars)
	source := normalizeTags(in.Source)
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return RenderOutput{}, err
	}
	markerSuffix := hex.EncodeToString(token[:])
	headToken, widgetToken := headMarker+markerSuffix, widgetMarker+markerSuffix
	source = strings.ReplaceAll(source, headMarker, headToken)
	source = strings.ReplaceAll(source, widgetMarker, widgetToken)
	out, err := liquid.Render(ctx, source, vars, nil, liquid.Limits{MaxSourceBytes: len(source), MaxOutputBytes: 512 << 10})
	if err != nil {
		return RenderOutput{}, err
	}
	if strings.Count(out, headToken) != 1 || strings.Count(out, widgetToken) != 1 {
		return RenderOutput{}, ErrTemplate
	}
	if err := validateHTML(out, false); err != nil {
		return RenderOutput{}, err
	}
	if err := validateTagPositions(out); err != nil {
		return RenderOutput{}, err
	}
	// Only validated tenant style elements receive the response nonce. Trusted
	// head/widget fragments retain their own nonces when inserted below.
	var rendered strings.Builder
	origins := []string{}
	z := xhtml.NewTokenizer(strings.NewReader(out))
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			if z.Err() != io.EOF {
				return RenderOutput{}, errHTML
			}
			break
		}
		if tt == xhtml.StartTagToken || tt == xhtml.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "style" && in.Nonce != "" {
				attrs := t.Attr[:0]
				for _, a := range t.Attr {
					if a.Key != "nonce" {
						attrs = append(attrs, a)
					}
				}
				t.Attr = append(attrs, xhtml.Attribute{Key: "nonce", Val: in.Nonce})
				rendered.WriteString(t.String())
				continue
			}
			if t.Data == "img" {
				for _, a := range t.Attr {
					if a.Key == "src" {
						if o := AssetOrigin(a.Val); o != "" && !slices.Contains(origins, o) {
							origins = append(origins, o)
						}
					}
				}
			}
		}
		rendered.Write(z.Raw())
	}
	out = rendered.String()
	out = strings.Replace(out, headToken, in.Head, 1)
	out = strings.Replace(out, widgetToken, in.Widget, 1)
	if len(out) > 512<<10 {
		return RenderOutput{}, liquid.ErrLimit
	}
	return RenderOutput{HTML: out, AssetOrigins: origins}, nil
}

func escapeContext(values map[string]any) {
	for key, value := range values {
		switch v := value.(type) {
		case string:
			values[key] = html.EscapeString(v)
		case map[string]any:
			escapeContext(v)
		}
	}
}
