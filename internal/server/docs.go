package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// scalarVersion and scalarIntegrity pin the API reference UI on the
// jsDelivr CDN. To upgrade, change the version and recompute the hash:
//
//	curl -sL https://cdn.jsdelivr.net/npm/@scalar/api-reference@<v>/dist/browser/standalone.js \
//	  | openssl dgst -sha384 -binary | openssl base64 -A
const (
	scalarVersion   = "1.74.0"
	scalarIntegrity = "sha384-VXnKAz61Xwc3tbw1P+KKrUP7YbcsSl1Ik4is5UnogJyw9XEYZ5Ay/T1i0zPYtSZH"
)

const docsInlineScript = `Scalar.createApiReference('#app', { url: '/openapi.yaml' })`

var docsPage = []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>zeroauthy Authentication API</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@` + scalarVersion + `/dist/browser/standalone.js" integrity="` + scalarIntegrity + `" crossorigin="anonymous"></script>
  <script>` + docsInlineScript + `</script>
</body>
</html>
`)

// docsCSP allows only the pinned CDN script and the one inline bootstrap
// script (by hash). Scalar injects styles and may load fonts, hence the
// style and font allowances.
var docsCSP = func() string {
	sum := sha256.Sum256([]byte(docsInlineScript))
	inline := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	return "default-src 'none'; script-src " + inline + " https://cdn.jsdelivr.net; " +
		"style-src 'unsafe-inline'; font-src https: data:; img-src https: data:; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
}()

func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", docsCSP)
	_, _ = w.Write(docsPage)
}
