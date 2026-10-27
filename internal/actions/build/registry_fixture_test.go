package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixturePackage is one version of a package served by the fixture registry.
type fixturePackage struct {
	name, version string
	files         map[string]string // relative to package/; package.json is generated
	scripts       map[string]string
}

// registry is a local npm registry: packuments at /<name> (scoped names as
// /@scope%2fname) and tarballs generated in-test. It never contacts the
// public registry.
type registry struct {
	*httptest.Server
	hits atomic.Int64 // requests served
}

// fixtureRegistry serves:
//
//   - za-pad 1.0.0 and 1.1.0 (latest 1.1.0)
//   - za-left 1.0.0 and 2.0.0 (latest 2.0.0)
//   - @za/scoped 2.0.0
//   - za-post 1.0.0, whose preinstall/install/postinstall scripts would write
//     marker if they ever ran
//   - za-big 1.0.0, with a 2 MB incompressible file
//   - za-slow 1.0.0, whose tarball never arrives
func fixtureRegistry(t *testing.T, marker string) *registry {
	t.Helper()
	big := make([]byte, 2<<20)
	_, _ = rand.Read(big)
	write := `node -e "require('fs').writeFileSync('` + marker + `', 'ran')" || touch '` + marker + `'`
	pkgs := []fixturePackage{
		{name: "za-pad", version: "1.0.0", files: map[string]string{"index.js": `module.exports = (s) => "[" + s + "]";`}},
		{name: "za-pad", version: "1.1.0", files: map[string]string{"index.js": `module.exports = (s) => "<" + s + ">";`}},
		{name: "za-left", version: "1.0.0", files: map[string]string{"index.js": `module.exports = "left-1";`}},
		{name: "za-left", version: "2.0.0", files: map[string]string{"index.js": `module.exports = "left-2";`}},
		{name: "@za/scoped", version: "2.0.0", files: map[string]string{"index.js": `module.exports = "scoped";`}},
		{name: "za-post", version: "1.0.0", files: map[string]string{"index.js": `module.exports = 1;`},
			scripts: map[string]string{"preinstall": write, "install": write, "postinstall": write}},
		{name: "za-big", version: "1.0.0", files: map[string]string{"index.js": `module.exports = 1;`, "blob.bin": string(big)}},
		{name: "za-slow", version: "1.0.0", files: map[string]string{"index.js": `module.exports = 1;`}},
	}
	latest := map[string]string{"za-pad": "1.1.0", "za-left": "2.0.0"}

	r := &registry{}
	tarballs := map[string][]byte{}
	packuments := map[string]map[string]any{}
	r.Server = httptest.NewUnstartedServer(nil)
	base := "http://" + r.Listener.Addr().String()
	for _, p := range pkgs {
		manifest := map[string]any{"name": p.name, "version": p.version, "main": "index.js"}
		if p.scripts != nil {
			manifest["scripts"] = p.scripts
		}
		pj, _ := json.Marshal(manifest)
		files := map[string]string{"package.json": string(pj)}
		for k, v := range p.files {
			files[k] = v
		}
		tgz := packTarball(t, files)
		short := p.name[strings.LastIndex(p.name, "/")+1:]
		tarPath := "/" + p.name + "/-/" + short + "-" + p.version + ".tgz"
		tarballs[tarPath] = tgz
		s1, s512 := sha1.Sum(tgz), sha512.Sum512(tgz)
		manifest["dist"] = map[string]string{
			"tarball":   base + tarPath,
			"shasum":    hex.EncodeToString(s1[:]),
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:]),
		}
		doc := packuments[p.name]
		if doc == nil {
			doc = map[string]any{"name": p.name, "dist-tags": map[string]string{"latest": p.version}, "versions": map[string]any{}}
			packuments[p.name] = doc
		}
		doc["versions"].(map[string]any)[p.version] = manifest
		if l, ok := latest[p.name]; ok {
			doc["dist-tags"] = map[string]string{"latest": l}
		}
	}
	r.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		path := req.URL.Path // %2f in a scoped name is decoded to /
		if strings.HasSuffix(path, ".tgz") {
			if strings.Contains(path, "za-slow") {
				select {
				case <-req.Context().Done():
				case <-time.After(30 * time.Second):
				}
				return
			}
			b, ok := tarballs[path]
			if !ok {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(b)
			return
		}
		doc, ok := packuments[strings.TrimPrefix(path, "/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	r.Start()
	t.Cleanup(r.Close)
	return r
}

func packTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
