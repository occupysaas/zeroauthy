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
