package logscrub

import (
	"context"
	"encoding/json"
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

// DetachedScrubber snapshots only the immutable registered mask values. The
// returned function retains no request context, cancellation, or unrelated
// context values, and may safely scrub enrichment produced after a request ends.
// Each invocation uses the same key/value and encoded-JSON policies as
// ScrubValueContext and returns an independent JSON-compatible value.
func DetachedScrubber(ctx context.Context) func(any) any {
	registered, _ := ctx.Value(valuesKey{}).([]string)
	values := slices.Clone(registered)
	return func(v any) any {
		maskCtx := context.WithValue(context.Background(), valuesKey{}, values)
		return ScrubValueContext(maskCtx, v)
	}
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

// maskValue only receives the independent JSON-compatible tree from ScrubValue.
func maskValue(ctx context.Context, v any) any {
	switch v := v.(type) {
	case string:
		if v == Marker {
			return v
		}
		trimmed := strings.TrimSpace(v)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			if decoded, err := decode([]byte(trimmed)); err == nil {
				// Decode keys and values before masking: JSON escaping must not
				// conceal a submitted password from its exact-value mask.
				encoded, err := json.Marshal(maskValue(ctx, decoded))
				if err != nil {
					return Marker
				}
				return string(encoded)
			}
		}
		return MaskText(ctx, v)
	case map[string]any:
		if v == nil {
			return v
		}
		out := make(map[string]any, len(v))
		for key, value := range v {
			key = MaskText(ctx, key)
			if _, exists := out[key]; exists {
				// Never pick a collision winner based on map iteration order.
				out[key] = Marker
			} else {
				out[key] = maskValue(ctx, value)
			}
		}
		return out
	case []any:
		for i, value := range v {
			v[i] = maskValue(ctx, value)
		}
	}
	return v
}

// WithCredentials masks every nonempty credential, including short OTPs and
// passwords. WithValues retains its conservative general free-text contract.
func WithCredentials(ctx context.Context, values ...string) context.Context {
	registered, _ := ctx.Value(valuesKey{}).([]string)
	merged := slices.Clone(registered)
	for _, value := range values {
		if value != "" && !slices.Contains(merged, value) {
			merged = append(merged, value)
		}
	}
	return context.WithValue(ctx, valuesKey{}, merged)
}

// CopyMasks copies only registered masks to an independent destination context.
// Background script output may outlive a request and must not retain it.
func CopyMasks(dst, src context.Context) context.Context {
	values, _ := src.Value(valuesKey{}).([]string)
	return WithCredentials(dst, values...)
}

// ScrubTruncatedText protects console lines that an upstream runner may have
// truncated. At or above the runner's minimum cut length, a credential prefix
// at the cut is hidden too. Over-hiding a coincidental suffix is intentional.
func ScrubTruncatedText(ctx context.Context, text string, minimumCut int) string {
	if len(text) >= minimumCut {
		values, _ := ctx.Value(valuesKey{}).([]string)
		cut := len(text)
		for _, value := range values {
			for size := min(len(value)-1, len(text)); size > 0; size-- {
				if strings.HasSuffix(text, value[:size]) {
					cut = min(cut, len(text)-size)
					break
				}
			}
		}
		if cut < len(text) {
			text = text[:cut] + Marker
		}
	}
	return ScrubValueContext(ctx, text).(string)
}
