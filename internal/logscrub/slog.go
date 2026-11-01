package logscrub

import (
	"context"
	"log/slog"
	"slices"
)

type handler struct {
	next slog.Handler
	ops  []operation
}

type operation struct {
	group string
	attrs []slog.Attr
}

// Handler scrubs message text and every attribute before forwarding a record.
// Bound attributes stay inside this wrapper until Handle: request-scoped masks
// are unavailable when a shared logger is constructed with With/WithGroup.
// Install it before binding attributes; attributes already bound inside next
// are opaque to the slog.Handler interface and cannot be inspected here.
func Handler(next slog.Handler) slog.Handler { return &handler{next: next} }

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{next: h.next, ops: append(slices.Clone(h.ops), operation{attrs: slices.Clone(attrs)})}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{next: h.next, ops: append(slices.Clone(h.ops), operation{group: name})}
}

func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make([]slog.Attr, 0, record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool { attrs = append(attrs, a); return true })
	clean := slog.NewRecord(record.Time, record.Level, ScrubValueContext(ctx, record.Message).(string), record.PC)
	clean.AddAttrs(scrubAttrs(ctx, boundAttrs(h.ops, attrs))...)
	return h.next.Handle(ctx, clean)
}

// Reconstitute the ordered With/WithGroup operations into one attribute tree.
// Each group contains only later bindings and record attributes, exactly as in
// slog; sensitive group names can then replace the whole nested value.
func boundAttrs(ops []operation, record []slog.Attr) []slog.Attr {
	var attrs []slog.Attr
	for i, op := range ops {
		if op.group != "" {
			children := boundAttrs(ops[i+1:], record)
			if len(children) > 0 {
				attrs = append(attrs, slog.Attr{Key: op.group, Value: slog.GroupValue(children...)})
			}
			return attrs
		}
		attrs = append(attrs, op.attrs...)
	}
	return append(attrs, record...)
}

func scrubAttrs(ctx context.Context, attrs []slog.Attr) []slog.Attr {
	attrs = inlineAttrs(attrs)
	type nameState struct {
		original           string
		collision, emitted bool
	}
	names := make(map[string]nameState, len(attrs))
	maskedKeys := make([]string, len(attrs))
	for i, attr := range attrs {
		key := MaskText(ctx, attr.Key)
		maskedKeys[i] = key
		if prior, exists := names[key]; exists {
			prior.collision = prior.collision || prior.original != attr.Key
			names[key] = prior
		} else {
			names[key] = nameState{original: attr.Key}
		}
	}
	out := make([]slog.Attr, 0, len(attrs))
	for i, attr := range attrs {
		key := maskedKeys[i]
		state := names[key]
		if state.collision {
			if state.emitted {
				continue
			}
			state.emitted = true
			names[key] = state
			attr.Value = slog.StringValue(Marker)
		} else if SensitiveKey(attr.Key) {
			attr.Value = slog.StringValue(Marker)
		} else {
			attr.Value = attr.Value.Resolve()
			switch attr.Value.Kind() {
			case slog.KindString:
				attr.Value = slog.StringValue(ScrubValueContext(ctx, attr.Value.String()).(string))
			case slog.KindGroup:
				attr.Value = slog.GroupValue(scrubAttrs(ctx, attr.Value.Group())...)
			case slog.KindAny:
				if err, ok := attr.Value.Any().(error); ok {
					attr.Value = slog.StringValue(ScrubValueContext(ctx, err.Error()).(string))
				} else {
					attr.Value = slog.AnyValue(ScrubValueContext(ctx, attr.Value.Any()))
				}
			}
		}
		attr.Key = key
		out = append(out, attr)
	}
	return out
}

// Empty-key groups share their parent's key namespace in slog. Expand them
// before detecting masking collisions with siblings or other inline groups.
func inlineAttrs(attrs []slog.Attr) []slog.Attr {
	var out []slog.Attr
	for _, attr := range attrs {
		if attr.Key == "" {
			attr.Value = attr.Value.Resolve()
			if attr.Value.Kind() == slog.KindGroup {
				out = append(out, inlineAttrs(attr.Value.Group())...)
				continue
			}
		}
		out = append(out, attr)
	}
	return out
}
