package webauthnrules_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// knownRulings returns the LR33b numbers D-0062 records: the numbers it names
// and every number in a range it adopts (spec §13 holds the table D-0062
// incorporates as "LR33b-1…37").
func knownRulings(t *testing.T) map[int]bool {
	t.Helper()
	b, err := os.ReadFile("../../docs/compat/decisions.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## D-0062 ")
	if start < 0 {
		t.Fatal("D-0062 missing from docs/compat/decisions.md")
	}
	section := text[start+1:]
	if end := strings.Index(section, "\n## D-"); end >= 0 {
		section = section[:end]
	}
	known := map[int]bool{}
	for _, m := range regexp.MustCompile(`LR33b-(\d+)(?:\s*(?:…|\.\.\.|–)\s*(\d+))?`).FindAllStringSubmatch(section, -1) {
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		for n := lo; n <= hi; n++ {
			known[n] = true
		}
	}
	// The adopted range must match the spec's ruling table row by row.
	spec, err := os.ReadFile("../../docs/superpowers/specs/2026-11-05-zeroauthy-passkeys-webauthn-design.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[int]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\| LR33b-(\d+) \|`).FindAllStringSubmatch(string(spec), -1) {
		n, _ := strconv.Atoi(m[1])
		rows[n] = true
	}
	for n := range known {
		if !rows[n] {
			t.Errorf("D-0062 adopts LR33b-%d but the spec ruling table has no such row", n)
		}
	}
	return known
}

func TestPasskeysGuideCitesKnownRulings(t *testing.T) {
	known := knownRulings(t)
	b, err := os.ReadFile("../../docs/passkeys.md")
	if err != nil {
		t.Fatal(err)
	}
	cited := regexp.MustCompile(`LR33b-(\d+)`).FindAllStringSubmatch(string(b), -1)
	if len(cited) == 0 {
		t.Fatal("docs/passkeys.md cites no local rulings; its differences section must name them")
	}
	for _, m := range cited {
		n, _ := strconv.Atoi(m[1])
		if !known[n] {
			t.Errorf("docs/passkeys.md cites %s, which D-0062 does not record", m[0])
		}
	}
	if !strings.Contains(string(b), "D-0062") {
		t.Error("docs/passkeys.md does not point readers at D-0062")
	}
}
