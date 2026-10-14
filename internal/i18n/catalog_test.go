package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

var templateKey = regexp.MustCompile(`\{\{-?\s*t\s+\.(?:Tenant\.)?L\s+"([^"]+)"`)

// usedKeys collects keys named in templates and the Key* constants.
func usedKeys(t *testing.T) []string {
	t.Helper()
	var used []string
	files, err := filepath.Glob("../ui/templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range templateKey.FindAllStringSubmatch(string(b), -1) {
			used = append(used, m[1])
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "keys.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, _ := strconv.Unquote(lit.Value)
			used = append(used, s)
		}
		return true
	})
	return used
}

func TestCatalogMatchesUsage(t *testing.T) {
	used := usedKeys(t)
	for _, k := range used {
		if _, ok := catalogs["en"][k]; !ok {
			t.Errorf("key %q is used but missing from en.json", k)
		}
	}
	for _, k := range EnglishKeys() {
		if !slices.Contains(used, k) {
			t.Errorf("en.json key %q is never used", k)
		}
	}
}

// Every other catalog may only contain English keys, with the same
// placeholders.
func TestOtherCatalogsMatchEnglish(t *testing.T) {
	for tag, texts := range catalogs {
		if tag == "en" {
			continue
		}
		for k, v := range texts {
			en, ok := catalogs["en"][k]
			if !ok {
				t.Errorf("%s: unknown key %q", tag, k)
				continue
			}
			if !slices.Equal(Placeholders(en), Placeholders(v)) {
				t.Errorf("%s: %q placeholders %v, English has %v", tag, k, Placeholders(v), Placeholders(en))
			}
		}
	}
}
