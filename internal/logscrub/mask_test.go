package logscrub

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestMaskValuesStopsWithoutCopyingRequestHistory(t *testing.T) {
	ctx := WithCredentials(context.Background(), "a", "bc", "猫", "four")
	var got []string
	for value := range MaskValues(ctx) {
		got = append(got, value)
		if len(got) == 2 {
			break
		}
	}
	if !reflect.DeepEqual(got, []string{"a", "bc"}) {
		t.Fatalf("values=%q", got)
	}
	if text := MaskText(ctx, "a bc 猫 four"); text != Marker+" "+Marker+" "+Marker+" "+Marker {
		t.Fatalf("source mutated: %q", text)
	}
}

func TestScrubTruncatedTextWithMaskOriginalSpans(t *testing.T) {
	for _, tt := range []struct{ text, want string }{
		{"prefix-middle-suffix middle", Marker + " CONFIG"},
		{strings.Repeat("x", 20) + "prefix-middle-suff", strings.Repeat("x", 20) + Marker},
		{`{"\u0070refix-middle-suffix":"\u0070refix-middle-suffix","password":"hidden"}`, `{"` + Marker + `":"` + Marker + `","password":"` + Marker + `"}`},
		{`{"prefix-middle-suffix-a":"one","prefix-middle-suffix-b":"two"}`, `{"` + Marker + `-a":"one","` + Marker + `-b":"two"}`},
	} {
		ctx := WithCredentials(context.Background(), "prefix-middle-suffix")
		if got := ScrubTruncatedTextWithMask(ctx, tt.text, 20, []string{"middle"}, "CONFIG"); got != tt.want {
			t.Errorf("got=%q want=%q", got, tt.want)
		}
	}
}

func TestScrubTruncatedTextEscapedOriginalSpans(t *testing.T) {
	for _, tc := range []struct{ name, credential, configured, text, want string }{
		{"node_literal_and_html", "\\u003c<\nbreak", "", `warn: "\\u003c<\nbreak"`, `warn: "` + Marker + `"`},
		{"prefixed", "line\nbreak\"value", "", `warn: "line\nbreak\"value"`, `warn: "` + Marker + `"`},
		{"cut", "line\nbreak\"value", "", strings.Repeat("x", 20) + `"line\nbreak`, strings.Repeat("x", 20) + `"` + Marker},
		{"escaped_overlap", "prefix-\n-middle-suffix", "\n-middle", `warn: prefix-\n-middle-suffix`, "warn: " + Marker},
		{"config_covers", "\n-middle", "prefix-\n-middle-suffix", `warn: prefix-\n-middle-suffix`, "warn: CONFIG"},
		{"config_escaped", "", "line\nbreak\"value", `warn: "line\nbreak\"value"`, `warn: "CONFIG"`},
		{"config_cut", "", "line\nbreak\"value", strings.Repeat("x", 20) + `line\nbreak`, strings.Repeat("x", 20) + "CONFIG"},
		{"raw_json_credential", `"quoted-secret"`, "", `"quoted-secret"`, Marker},
		{"raw_object_credential", `{"value":"json-secret"}`, "", `{"value":"json-secret"}`, Marker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithCredentials(context.Background(), tc.credential)
			if got := ScrubTruncatedTextWithMask(ctx, tc.text, 20, []string{tc.configured}, "CONFIG"); got != tc.want {
				t.Errorf("got=%q want=%q", got, tc.want)
			}
		})
	}
}
