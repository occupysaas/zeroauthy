// Package console embeds zeroauthy's admin console: the Vue application in
// this directory, built into dist/ by `make console`. dist/ is committed so
// that `go build` and `go install` work without Node.
package console

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files is the built console, rooted at dist/: index.html and assets/.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is a literal directory of the embed
	}
	return sub
}
