// Package dictionary holds the common-password lists a connection's
// dictionary rule checks against. The lists are data files (see NOTICE for
// their source and licence), embedded and parsed once, on first use.
package dictionary

import (
	"bufio"
	"bytes"
	"embed"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

//go:embed en_10k.txt en_100k.txt
var files embed.FS

var (
	mu    sync.Mutex
	lists = map[string]map[string]struct{}{}
)

// Fold returns s in the form used to compare passwords with list entries
// and profile values: Unicode-normalized (NFC) and case-folded, so "Éclair"
// equals "éCLAIR" and "STRASSE" equals "Straße".
func Fold(s string) string {
	return cases.Fold().String(norm.NFC.String(s))
}

// load returns the folded entries of the named default list, nil when the
// name is not one of them.
func load(name string) map[string]struct{} {
	mu.Lock()
	defer mu.Unlock()
	if set, ok := lists[name]; ok {
		return set
	}
	data, err := files.ReadFile(name + ".txt")
	if err != nil {
		return nil
	}
	set := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" {
			set[Fold(w)] = struct{}{}
		}
	}
	lists[name] = set
	return set
}

// InDefault reports whether word equals, ignoring case, an entry of the
// named default list ("en_10k" or "en_100k"). An unknown name holds nothing.
func InDefault(name, word string) bool {
	_, ok := load(name)[Fold(word)]
	return ok
}

// Size returns the number of distinct entries of the named default list.
func Size(name string) int { return len(load(name)) }
