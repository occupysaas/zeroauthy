package protection

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBreachFile(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		bad        bool
	}{{"sorted", digest("päss🔑") + ":2\n", false}, {"zero", digest("pw") + ":0\n", true}, {"corrupt", "password:2\n", true}, {"unsorted", strings.Repeat("F", 40) + ":1\n" + strings.Repeat("A", 40) + ":1\n", true}, {"empty", "", true}, {"oversized line", strings.Repeat("A", 100000), true}, {"negative", digest("pw") + ":-1\n", true}, {"overflow", digest("pw") + ":18446744073709551616\n", true}, {"duplicate", digest("pw") + ":1\n" + digest("pw") + ":2\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "corpus")
			os.WriteFile(p, []byte(tc.body), 0600)
			c, err := NewFileChecker(p)
			if (err != nil) != tc.bad {
				t.Fatal(err)
			}
			if err != nil {
				return
			}
			defer c.Close()
			hit, err := c.Check(context.Background(), "päss🔑")
			if !hit || err != nil {
				t.Fatal(hit, err)
			}
			hit, err = c.Check(context.Background(), "absent")
			if hit || err != nil {
				t.Fatal(hit, err)
			}
		})
	}
	if _, err := NewFileChecker(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing accepted")
	}
}
func TestBreachFileIndex(t *testing.T) {
	var lines []string
	for i := 0; i < 10000; i++ {
		lines = append(lines, digest(fmt.Sprint(i))+":1\n")
	}
	sort.Strings(lines)
	p := filepath.Join(t.TempDir(), "corpus")
	os.WriteFile(p, []byte(strings.Join(lines, "")), 0600)
	c, err := NewFileChecker(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(c.index) > 41 {
		t.Fatal("not sparse", len(c.index))
	}
	for _, p := range []string{"0", "123", "9999"} {
		hit, err := c.Check(context.Background(), p)
		if !hit || err != nil {
			t.Fatal(p, hit, err)
		}
	}
}
func TestBreachFileModifiedUnavailable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "corpus")
	os.WriteFile(p, []byte(digest("secret")+":1\n"), 0600)
	c, err := NewFileChecker(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(context.Background(), "secret"); err == nil {
		t.Fatal("truncated corpus reported clean")
	}
}
