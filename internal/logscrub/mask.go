package logscrub

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"
)

type valuesKey struct{}

// WithValues derives an immutable request mask. Short values are intentionally
// ignored to avoid replacing commonplace words or fragments of unrelated data.
func WithValues(ctx context.Context, values ...string) context.Context {
	registered, _ := ctx.Value(valuesKey{}).([]string)
	merged := slices.Clone(registered)
	for _, value := range values {
		if utf8.RuneCountInString(value) >= 4 && !slices.Contains(merged, value) {
			merged = append(merged, value)
		}
	}
	return context.WithValue(ctx, valuesKey{}, merged)
}

// MaskText replaces exact registered values, merging overlapping occurrences.
// Matches are found in the original text, so replacement markers are never
// themselves remasked or used to interfere with another replacement.
func MaskText(ctx context.Context, s string) string {
	values, _ := ctx.Value(valuesKey{}).([]string)
	type span struct{ start, end int }
	var spans []span
	for _, value := range values {
		for offset := 0; offset < len(s); {
			i := strings.Index(s[offset:], value)
			if i < 0 {
				break
			}
			start := offset + i
			spans = append(spans, span{start, start + len(value)})
			offset = start + 1
		}
	}
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	var out strings.Builder
	last := 0
	for i := 0; i < len(spans); {
		current := spans[i]
		i++
		for i < len(spans) && spans[i].start < current.end {
			current.end = max(current.end, spans[i].end)
			i++
		}
		out.WriteString(s[last:current.start])
		out.WriteString(Marker)
		last = current.end
	}
	out.WriteString(s[last:])
	return out.String()
}
