package actionsrules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestEventStreamTriggerSupported(t *testing.T) {
	if errs := NormalizeAction(&store.Action{Name: "Stream", Trigger: "event-stream"}); len(errs) > 0 {
		t.Fatal(errs)
	}
}
