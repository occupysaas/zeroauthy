package logscrub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

func TestSlogMasksDynamicKeys(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "hunter2!!", "password")
	for _, bound := range []bool{false, true} {
		var output bytes.Buffer
		log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
		attrs := []slog.Attr{slog.String("hunter2!!", "keep"), slog.String("password", "hidden")}
		if bound {
			log = log.With(attrs[0], attrs[1])
			attrs = nil
		}
		log.LogAttrs(ctx, slog.LevelInfo, "request", attrs...)
		if strings.Contains(output.String(), "hunter2!!") || strings.Contains(output.String(), "password") || strings.Contains(output.String(), "hidden") {
			t.Errorf("bound=%v dynamic key or original-sensitive value leaked: %s", bound, output.String())
		}
		var got map[string]any
		if err := json.Unmarshal(output.Bytes(), &got); err != nil || got["[REDACTED]"] != "[REDACTED]" {
			t.Errorf("bound=%v collision did not fail closed: %s, %v", bound, output.String(), err)
		}
	}
}

func TestSlogMasksDynamicGroupNames(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "hunter2!!", "password")
	for _, bound := range []bool{false, true} {
		var output bytes.Buffer
		log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
		if bound {
			log.WithGroup("hunter2!!").With("public", "keep").InfoContext(ctx, "request")
		} else {
			log.InfoContext(ctx, "request", slog.Group("hunter2!!", slog.String("public", "keep")))
		}
		if strings.Contains(output.String(), "hunter2!!") {
			t.Errorf("bound=%v dynamic group leaked: %s", bound, output.String())
		}
		var got map[string]any
		if err := json.Unmarshal(output.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		group, ok := got["[REDACTED]"].(map[string]any)
		if !ok || group["public"] != "keep" {
			t.Errorf("bound=%v public group structure lost: %s", bound, output.String())
		}
		output.Reset()
		log.WithGroup("password").InfoContext(ctx, "request", "public", "hidden")
		got = nil
		if err := json.Unmarshal(output.Bytes(), &got); err != nil || got["[REDACTED]"] != "[REDACTED]" || strings.Contains(output.String(), "hidden") {
			t.Errorf("original sensitive group was not hidden: %s, %v", output.String(), err)
		}
	}
}

func TestSlogMasksAnyAndEmbeddedJSONKeys(t *testing.T) {
	secret := "hunter\"2\\phrase"
	ctx := logscrub.WithValues(context.Background(), secret)
	doc := map[string]any{secret: "keep", "public": "visible"}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
	log.With("bound", string(encoded)).InfoContext(ctx, string(encoded), "payload", doc)
	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"bound", "msg"} {
		var object map[string]any
		if err := json.Unmarshal([]byte(got[key].(string)), &object); err != nil {
			t.Fatal(err)
		}
		if object["[REDACTED]"] != "keep" || object["public"] != "visible" {
			t.Errorf("%s encoded key leaked or lost public data: %#v", key, object)
		}
	}
	if got["payload"].(map[string]any)["[REDACTED]"] != "keep" {
		t.Errorf("Any object key leaked: %#v", got)
	}
	if doc[secret] != "keep" || len(doc) != 2 {
		t.Fatal("masking mutated caller's object")
	}
}

func TestScrubContextMasksJSONKeys(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "hunter2!!", "password")
	input := []byte(`{"hunter2!!":"keep","nested":[{"password":"hidden","public":"visible"}],"body":"{\"hunter2!!\":\"keep\"}"}`)
	output, err := logscrub.ScrubContext(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "hunter2!!") || strings.Contains(string(output), "password") || strings.Contains(string(output), "hidden") {
		t.Fatalf("context JSON scrub leaked key text: %s", output)
	}
	if got["[REDACTED]"] != "keep" || got["nested"].([]any)[0].(map[string]any)["[REDACTED]"] != "[REDACTED]" {
		t.Fatalf("original sensitivity or JSON structure lost: %s", output)
	}
	var nested map[string]any
	if err := json.Unmarshal([]byte(got["body"].(string)), &nested); err != nil || nested["[REDACTED]"] != "keep" {
		t.Fatalf("encoded key text survived: %s, %v", output, err)
	}
	if _, err := logscrub.ScrubContext(ctx, []byte(`{} {}`)); err == nil {
		t.Fatal("context scrub accepted multiple JSON documents")
	}
}

func TestScrubValueContextKeyCollisionsFailClosed(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "hunter2!!", "ticket123")
	input := map[string]any{"hunter2!!": "first", "ticket123": "second", "[REDACTED]": "third", "public": "visible"}
	for range 20 { // map order must not select a collision winner.
		got := logscrub.ScrubValueContext(ctx, input).(map[string]any)
		if len(got) != 2 || got["[REDACTED]"] != "[REDACTED]" || got["public"] != "visible" {
			t.Fatalf("colliding keys were not redacted deterministically: %#v", got)
		}
	}
	if input["hunter2!!"] != "first" || len(input) != 4 {
		t.Fatal("context scrub mutated caller's keys")
	}
	parent := logscrub.ScrubValueContext(context.Background(), input).(map[string]any)
	if parent["hunter2!!"] != "first" || parent["ticket123"] != "second" {
		t.Fatalf("request masks escaped their context: %#v", parent)
	}
}

func TestSlogDynamicKeyCollisionsFailClosed(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "hunter2!!", "ticket123")
	var output bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
	log.With("hunter2!!", "first").InfoContext(ctx, "request", "ticket123", "second", "[REDACTED]", "third", "public", "visible")
	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got["[REDACTED]"] != "[REDACTED]" || got["public"] != "visible" {
		t.Fatalf("attr collision did not fail closed: %s, %v", output.String(), err)
	}
	if strings.Contains(output.String(), "first") || strings.Contains(output.String(), "second") || strings.Contains(output.String(), "third") {
		t.Fatalf("one collision value survived: %s", output.String())
	}
	output.Reset()
	log.InfoContext(ctx, "request", slog.Group("hunter2!!", slog.String("note", "first")), slog.String("ticket123", "second"))
	got = nil
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got["[REDACTED]"] != "[REDACTED]" {
		t.Fatalf("group/attribute collision did not fail closed: %s, %v", output.String(), err)
	}
	output.Reset()
	log.InfoContext(ctx, "request", slog.Group("", slog.String("hunter2!!", "first")), slog.String("ticket123", "second"))
	got = nil
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got["[REDACTED]"] != "[REDACTED]" {
		t.Fatalf("inline-group collision did not fail closed: %s, %v", output.String(), err)
	}
}

type countedLogValue struct{ calls *int }

func (v countedLogValue) LogValue() slog.Value {
	*v.calls++
	if *v.calls == 1 {
		return slog.StringValue("keep")
	}
	return slog.StringValue("changed")
}

func TestSlogInlineNormalizationResolvesValueOnce(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
	calls := 0
	log.Info("request", slog.Any("", countedLogValue{calls: &calls}))
	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got[""] != "keep" {
		t.Fatalf("inline normalization changed the resolved value: %s, %v", output.String(), err)
	}
}
