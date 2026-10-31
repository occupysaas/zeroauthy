package logscrub

import (
	"context"
	"reflect"
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
