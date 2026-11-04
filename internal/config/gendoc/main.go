// Command gendoc writes docs/configuration.md from the config package.
// It runs from `go generate ./...` (see internal/config/reference.go).
package main

import (
	"flag"
	"log"
	"os"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func main() {
	src := flag.String("src", ".", "directory of the config package source")
	out := flag.String("out", config.ReferencePath, "output Markdown file")
	flag.Parse()
	b, err := config.Reference(*src)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}
