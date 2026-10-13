package server

import "net/http"

// scalarVersion pins the API reference UI loaded from the jsDelivr CDN.
const scalarVersion = "1.74.0"

var docsPage = []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>zeroauthy Authentication API</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@` + scalarVersion + `"></script>
  <script>Scalar.createApiReference('#app', { url: '/openapi.yaml' })</script>
</body>
</html>
`)

func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(docsPage)
}
