package providers

import (
	"bytes"
	"flag"
	"os"
	"testing"
)

var updateConsole = flag.Bool("update-console", false, "rewrite the console descriptor summary")

const consolePath = "../../../console/src/pages/connections/social/descriptors.json"

// TestConsoleDescriptorsCurrent keeps the console's descriptor summary equal
// to the embedded descriptors. Regenerate with
// go test ./internal/federation/providers -run ConsoleDescriptors -update-console.
func TestConsoleDescriptorsCurrent(t *testing.T) {
	want, err := ConsoleSummary()
	if err != nil {
		t.Fatal(err)
	}
	if *updateConsole {
		if err := os.WriteFile(consolePath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(consolePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; rerun with -update-console", consolePath)
	}
}
