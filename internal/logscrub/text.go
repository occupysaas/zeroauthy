package logscrub

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

// ScrubTruncatedTextWithMask applies registered credentials and an additional
// group of values to the original text in one pass. Additional-only matches use
// replacement, including values also registered in ctx. Overlapping matches hide
// the entire connected span: a covering additional match keeps its replacement;
// otherwise a credential that extends the span uses Marker. At or above
// minimumCut, a value's trailing partial prefix participates in the same union.
// JSON strings are decoded before matching keys/values; secret keys and masked
// key collisions keep the same policy as ScrubValueContext.
func ScrubTruncatedTextWithMask(ctx context.Context, text string, minimumCut int, additional []string, replacement string) string {
	configured := make(map[string]struct{}, len(additional))
	for _, value := range additional {
		if value != "" {
			configured[value] = struct{}{}
		}
	}
	type literal struct {
		value      string
		credential bool
	}
	var literals []literal
	// Match both the original value and its JSON string spelling against the
	// original text. Severity prefixes and cutoffs may leave invalid JSON, so
	// decoding the line alone cannot protect an escaped credential. Keep these
	// variants in the same span union to preserve configuration overlap policy.
	add := func(value string, credential bool) {
		literals = append(literals, literal{value, credential})
		encoded, _ := json.Marshal(value)
		escaped := string(encoded[1 : len(encoded)-1])
		if escaped != value {
			literals = append(literals, literal{escaped, credential})
		}
		// JSON.stringify leaves HTML characters and line separators literal.
		var node strings.Builder
		for i := 0; i < len(escaped); {
			if escaped[i] == '\\' && i+1 < len(escaped) {
				if i+6 <= len(escaped) {
					var decoded string
					switch escaped[i : i+6] {
					case `\u003c`:
						decoded = "<"
					case `\u003e`:
						decoded = ">"
					case `\u0026`:
						decoded = "&"
					case `\u2028`:
						decoded = "\u2028"
					case `\u2029`:
						decoded = "\u2029"
					}
					if decoded != "" {
						node.WriteString(decoded)
						i += 6
						continue
					}
				}
				// Consume an escape atomically: a literal \\u003c must
				// remain literal rather than being decoded as HTML.
				node.WriteString(escaped[i : i+2])
				i += 2
				continue
			}
			node.WriteByte(escaped[i])
			i++
		}
		nodeEscaped := node.String()
		if nodeEscaped != value && nodeEscaped != escaped {
			literals = append(literals, literal{nodeEscaped, credential})
		}
	}
	for value := range MaskValues(ctx) {
		if _, exists := configured[value]; !exists {
			add(value, true)
		}
	}
	for value := range configured {
		add(value, false)
	}
	mask := func(s string) string {
		type span struct {
			start, end int
			credential bool
		}
		var spans []span
		for _, literal := range literals {
			value := literal.value
			for offset := 0; offset < len(s); {
				i := strings.Index(s[offset:], value)
				if i < 0 {
					break
				}
				start := offset + i
				spans = append(spans, span{start, start + len(value), literal.credential})
				offset = start + 1
			}
			if len(s) >= minimumCut {
				for size := min(len(value)-1, len(s)); size > 0; size-- {
					if strings.HasSuffix(s, value[:size]) {
						spans = append(spans, span{len(s) - size, len(s), literal.credential})
						break
					}
				}
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
			configuredEnd := 0
			if !current.credential {
				configuredEnd = current.end
			}
			i++
			for i < len(spans) && spans[i].start < current.end {
				if !spans[i].credential && spans[i].start == current.start {
					configuredEnd = max(configuredEnd, spans[i].end)
				}
				current.end = max(current.end, spans[i].end)
				current.credential = current.credential || spans[i].credential
				i++
			}
			out.WriteString(s[last:current.start])
			if current.credential && configuredEnd < current.end {
				out.WriteString(Marker)
			} else {
				out.WriteString(replacement)
			}
			last = current.end
		}
		out.WriteString(s[last:])
		return out.String()
	}
	// A credential can itself be valid JSON. Preserve a covering original
	// match before structured scrubbing changes its spelling or removes keys.
	if original := mask(text); original == Marker || original == replacement {
		return original
	}
	return maskValueWith(ScrubValue(text), mask).(string)
}
