// Package liquid exposes the bounded Liquid subset shared by email and hosted pages.
package liquid

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

type Limits struct{ MaxSourceBytes, MaxOutputBytes int }

var ErrLimit = errors.New("liquid limit exceeded")
var ErrSyntax = errors.New("invalid liquid source")

func Render(ctx context.Context, source string, vars map[string]any, tags map[string]string, limits Limits) (string, error) {
	maxSource := limits.MaxSourceBytes
	if maxSource == 0 {
		maxSource = 100 << 10
	}
	maxOutput := limits.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = 512 << 10
	}
	if !utf8.ValidString(source) || len(source) > maxSource {
		return "", ErrLimit
	}
	for name, value := range tags {
		source = strings.ReplaceAll(source, "{% "+name+" %}", value)
		source = strings.ReplaceAll(source, "{%- "+name+" -%}", value)
	}
	out, err := RenderLiquid(ctx, source, vars, maxOutput)
	if err != nil {
		return "", err
	}
	if len(out) > maxOutput {
		return "", ErrLimit
	}
	return out, nil
}
