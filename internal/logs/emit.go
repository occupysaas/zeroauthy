package logs

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
)

var eventDescriptions = func() map[string]string {
	out := map[string]string{}
	for _, code := range logrules.Codes() {
		if code.Emitted {
			out[code.Type] = code.Description
		}
	}
	return out
}()

// RecordEvent supplies the frozen catalog description at an outcome boundary.
// A missing recorder is the default no-op; deferred catalog codes stay disabled.
func RecordEvent(ctx context.Context, recorder Recorder, event Event) {
	description, enabled := eventDescriptions[event.Type]
	if !enabled {
		return
	}
	event = Enrich(ctx, event)
	if event.Description == "" {
		event.Description = description
	}
	if recorder == nil {
		recorder = Nop
	}
	recorder.Record(ctx, event)
}

type recorderKey struct{}

func WithRecorder(ctx context.Context, recorder Recorder) context.Context {
	if _, ok := ctx.Value(executionTraceKey{}).(*executionTrace); !ok {
		ctx = context.WithValue(ctx, executionTraceKey{}, &executionTrace{})
	}
	if recorder == nil {
		recorder = Nop
	}
	return context.WithValue(ctx, recorderKey{}, recorder)
}
func RecorderFromContext(ctx context.Context) Recorder {
	if recorder, ok := ctx.Value(recorderKey{}).(Recorder); ok {
		return recorder
	}
	return Nop
}
