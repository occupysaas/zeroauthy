package main

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "zeroauthy dev\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
