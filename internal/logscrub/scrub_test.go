package logscrub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

func TestScrubKeys(t *testing.T) {
	keys := []string{"password", "Password", "new_password", "client_secret", "x-api-key", "httpAuthorization", "id_token", "otp_code", "private_key", "passwd", "pwd", "credentials", "recovery.code", "prefixSECRETpostfix"}
	for _, key := range keys {
		for _, value := range []any{"hunter2!!", true, nil, 42, map[string]any{"visible": "hidden"}, []any{1, 2}} {
			input := map[string]any{key: value, "sibling": "public"}
			got := logscrub.ScrubValue(input).(map[string]any)
			if got[key] != logrules.Marker || got["sibling"] != "public" {
				t.Fatalf("%q (%T): %#v", key, value, got)
			}
			if !reflect.DeepEqual(input[key], value) {
				t.Fatal("ScrubValue mutated the caller's object")
			}
		}
	}
	for _, key := range []string{"email", "description", "user_id", "count"} {
		if logscrub.SensitiveKey(key) {
			t.Errorf("public key %q is sensitive", key)
		}
	}
	input := `{"metadata":{"a":[{"b":{"c":{"d":{"password":"hunter2!!","sibling":"public"}}}}]},"count":9007199254740993}`
	got, err := logscrub.Scrub([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "hunter2!!") || !strings.Contains(string(got), `"sibling":"public"`) || !strings.Contains(string(got), `9007199254740993`) {
		t.Fatalf("deep redaction or number precision lost: %s", got)
	}
}

func TestScrubJSONInString(t *testing.T) {
	inner, _ := json.Marshal(map[string]any{"password": "hunter2!!", "public": "keep"})
	array, _ := json.Marshal([]any{map[string]any{"api_key": "hidden", "again": string(inner)}})
	input, _ := json.Marshal(map[string]any{"details": map[string]any{"request": map[string]any{"body": string(array)}}})
	got, err := logscrub.Scrub(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "hunter2!!") || strings.Contains(string(got), "hidden") || !strings.Contains(string(got), "keep") {
		t.Fatalf("encoded JSON leaked or lost public value: %s", got)
	}
}

func TestScrubStrictJSON(t *testing.T) {
	for _, input := range []string{``, `{"password":`, `{} {"password":"secret"}`, `[] trailing`} {
		if got, err := logscrub.Scrub([]byte(input)); err == nil {
			t.Errorf("accepted malformed/multiple JSON documents %q: %s", input, got)
		}
	}
	// A string containing multiple documents is free text, not embedded JSON.
	input := `{} {"password":"hunter2!!"}`
	if got := logscrub.ScrubValue(input); got != input {
		t.Fatalf("changed non-JSON text: %#v", got)
	}
}

func TestScrubValueTypedJSON(t *testing.T) {
	input := []map[string]string{{"new_password": "hunter2!!", "name": "keep"}}
	got, err := json.Marshal(logscrub.ScrubValue(input))
	if err != nil || string(got) != `[{"name":"keep","new_password":"[REDACTED]"}]` {
		t.Fatalf("typed maps were not scrubbed: %s, %v", got, err)
	}
	if input[0]["new_password"] != "hunter2!!" {
		t.Fatal("mutated typed input")
	}
}

func TestScrubValueCyclesFailClosed(t *testing.T) {
	object := map[string]any{}
	object["self"] = object
	array := make([]any, 1)
	array[0] = array
	for _, input := range []any{object, array, make(chan string), json.Number("hunter2!!"), math.NaN(), math.Inf(1)} {
		got := logscrub.ScrubValue(input)
		encoded, err := json.Marshal(got)
		if err != nil || !bytes.Contains(encoded, []byte(`"[REDACTED]"`)) {
			t.Fatalf("unsupported or cyclic input did not fail closed: %s, %v", encoded, err)
		}
	}
	// Reusing an ordinary child is not a cycle and must retain public data.
	child := map[string]any{"name": "public"}
	got, err := json.Marshal(logscrub.ScrubValue([]any{child, child}))
	if err != nil || string(got) != `[{"name":"public"},{"name":"public"}]` {
		t.Fatalf("shared child misidentified as cycle: %s, %v", got, err)
	}
}

func TestScrubArbitraryDepth(t *testing.T) {
	input := strings.Repeat(`{"metadata":[`, 128) + `{"password":"hunter2!!","public":"keep"}` + strings.Repeat(`]}`, 128)
	got, err := logscrub.Scrub([]byte(input))
	if err != nil || strings.Contains(string(got), "hunter2!!") || !strings.Contains(string(got), `"public":"keep"`) {
		t.Fatalf("deep input was truncated or leaked: %s, %v", got, err)
	}
}

func TestSlogTypedAndUnsupportedValues(t *testing.T) {
	type payload struct {
		Password string `json:"password"`
		Public   string `json:"public"`
	}
	for _, value := range []any{
		map[string]string{"password": "hidden", "public": "keep"},
		[]payload{{Password: "hidden", Public: "keep"}},
		payload{Password: "hidden", Public: "keep"},
		json.RawMessage(`{"password":"hidden","public":"keep"}`),
		errors.New(`{"password":"hidden","public":"keep"}`),
	} {
		var output bytes.Buffer
		log := slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
		log.Info("request", "data", value)
		if strings.Contains(output.String(), "hidden") || !strings.Contains(output.String(), "keep") || !strings.Contains(output.String(), "[REDACTED]") {
			t.Errorf("typed value leaked: %s", output.String())
		}
	}
}

func TestMaskText(t *testing.T) {
	base := context.Background()
	ctx := logscrub.WithValues(base, "hunter2!!", "abc", "密碼秘密")
	if got := logscrub.MaskText(ctx, "login failed for hunter2!!; abc 密碼秘密"); got != "login failed for [REDACTED]; abc [REDACTED]" {
		t.Fatalf("masked text: %q", got)
	}
	if got := logscrub.MaskText(base, "hunter2!!"); got != "hunter2!!" {
		t.Fatalf("mutated parent: %q", got)
	}
	child := logscrub.WithValues(ctx, "another-secret")
	sibling := logscrub.WithValues(ctx, "sibling-secret")
	if got := logscrub.MaskText(child, "hunter2!! another-secret sibling-secret"); got != "[REDACTED] [REDACTED] sibling-secret" {
		t.Fatalf("child masks: %q", got)
	}
	if got := logscrub.MaskText(sibling, "another-secret sibling-secret"); got != "another-secret [REDACTED]" {
		t.Fatalf("sibling masks mutated: %q", got)
	}
	if got := logscrub.MaskText(ctx, "another-secret"); got != "another-secret" {
		t.Fatalf("child mutated parent: %q", got)
	}
}

func TestMaskTextOverlaps(t *testing.T) {
	ctx := logscrub.WithValues(context.Background(), "abcd", "abcdef", "defghi", "REDACTED")
	if got := logscrub.MaskText(ctx, "abcdefghi abcdef abcdefghi"); got != "[REDACTED] [REDACTED] [REDACTED]" {
		t.Fatalf("overlapping values or replacement marker were partially exposed: %q", got)
	}
}

type logValue struct{}

func (logValue) LogValue() slog.Value {
	return slog.GroupValue(slog.String("client_secret", "hidden"), slog.String("note", "hunter2!!"), slog.Int("count", 3))
}

func TestSlogHandlerScrubs(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&out, nil)))
	ctx := logscrub.WithValues(context.Background(), "hunter2!!")
	log.InfoContext(ctx, "failed hunter2!!", slog.String("password", "hidden"),
		slog.Group("details", slog.String("client_secret", "hidden"), slog.String("name", "keep")),
		slog.Any("resolved", logValue{}), slog.Any("error", errors.New("failed hunter2!!")),
		slog.Any("body", map[string]any{"password": "hidden", "note": "hunter2!!"}))
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "hunter2!!") || strings.Contains(out.String(), "hidden") {
		t.Fatalf("server log leaked: %s", out.String())
	}
	if got["msg"] != "failed [REDACTED]" || got["password"] != logrules.Marker || got["error"] != "failed [REDACTED]" {
		t.Fatalf("message/attribute mask: %#v", got)
	}
	if got["details"].(map[string]any)["name"] != "keep" || got["resolved"].(map[string]any)["count"] != float64(3) {
		t.Fatalf("public group attributes lost: %#v", got)
	}
}

func TestSlogBoundAttrsUseHandleContext(t *testing.T) {
	var out bytes.Buffer
	base := slog.New(logscrub.Handler(slog.NewJSONHandler(&out, nil)))
	bound := base.With("note", "hunter2!!").WithGroup("details").With("payload", map[string]any{"note": "hunter2!!", "api_key": "hidden"}).WithGroup("nested")
	ctx := logscrub.WithValues(context.Background(), "hunter2!!")
	bound.InfoContext(ctx, "request", slog.String("note", "hunter2!!"), slog.Int("count", 2))
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "hunter2!!") || strings.Contains(out.String(), "hidden") || got["note"] != logrules.Marker {
		t.Fatalf("bound attributes leaked: %s", out.String())
	}
	details := got["details"].(map[string]any)
	if details["payload"].(map[string]any)["note"] != logrules.Marker || details["nested"].(map[string]any)["count"] != float64(2) {
		t.Fatalf("bound group semantics lost: %#v", got)
	}
	out.Reset()
	bound.Info("other request", "public", "keep")
	if !strings.Contains(out.String(), "hunter2!!") {
		t.Fatalf("previous request mutated shared logger: %s", out.String())
	}
	out.Reset()
	base.InfoContext(ctx, "root", "public", "keep")
	if strings.Contains(out.String(), "details") || strings.Contains(out.String(), "note") {
		t.Fatalf("derived logger mutated base: %s", out.String())
	}
}

func TestSlogSensitiveGroup(t *testing.T) {
	var out bytes.Buffer
	base := slog.New(logscrub.Handler(slog.NewJSONHandler(&out, nil)))
	base.With("public", "keep").WithGroup("client_secret").With("x", "hidden").Info("request", "y", "hidden")
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["client_secret"] != logrules.Marker || got["public"] != "keep" || strings.Contains(out.String(), "hidden") {
		t.Fatalf("sensitive WithGroup leaked: %s", out.String())
	}
	out.Reset()
	base.WithGroup("").Info("request", slog.Group("", slog.String("public", "keep")), slog.Group("empty"))
	got = nil
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["public"] != "keep" || strings.Contains(out.String(), "empty") {
		t.Fatalf("inline/empty group semantics: %s (%v)", out.String(), err)
	}
}

func TestSlogEmbeddedJSONMasksDecodedValues(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&out, nil)))
	secret := "hunter\"2\\secret"
	body, err := json.Marshal(map[string]any{"note": secret, "password": "hidden", "public": "keep"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := logscrub.WithValues(context.Background(), secret)
	log.With("bound", string(body)).InfoContext(ctx, string(body), "body", string(body), "object", map[string]any{"encoded": string(body)})
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"msg", "body", "bound"} {
		var nested map[string]any
		if err := json.Unmarshal([]byte(got[key].(string)), &nested); err != nil {
			t.Fatal(err)
		}
		if nested["note"] != logrules.Marker || nested["password"] != logrules.Marker || nested["public"] != "keep" {
			t.Errorf("%s embedded secret retained: %#v", key, nested)
		}
	}
	var nested map[string]any
	if err := json.Unmarshal([]byte(got["object"].(map[string]any)["encoded"].(string)), &nested); err != nil {
		t.Fatal(err)
	}
	if nested["note"] != logrules.Marker {
		t.Errorf("Any embedded JSON retained secret: %#v", nested)
	}
}

func TestSlogEncodedJSONPreservesNumbersAndMarkers(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(&out, nil)))
	ctx := logscrub.WithValues(context.Background(), "1234", "REDACTED")
	log.InfoContext(ctx, "request", "body", `{"note":"1234","password":"hidden","count":1234}`)
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var nested map[string]any
	if err := json.Unmarshal([]byte(got["body"].(string)), &nested); err != nil {
		t.Fatalf("mask corrupted encoded JSON: %s, %v", out.String(), err)
	}
	if nested["note"] != logrules.Marker || nested["password"] != logrules.Marker || nested["count"] != float64(1234) {
		t.Fatalf("encoded JSON markers/numbers changed: %#v", nested)
	}
}

func TestShortCredentialsMaskedWithoutChangingWithValues(t *testing.T) {
	for _, secret := range []string{"a", "ab", "abc", "猫"} {
		t.Run(secret, func(t *testing.T) {
			if got := logscrub.MaskText(logscrub.WithValues(context.Background(), secret), secret); got != secret {
				t.Fatalf("generic short mask changed: %q", got)
			}
			ctx := logscrub.WithCredentials(context.Background(), secret)
			if got := logscrub.MaskText(ctx, secret); got != logscrub.Marker {
				t.Fatalf("credential not masked: %q", got)
			}
			detached := logscrub.CopyMasks(context.Background(), ctx)
			if got := logscrub.MaskText(detached, secret); got != logscrub.Marker {
				t.Fatalf("detached short mask lost: %q", got)
			}
		})
	}
}
