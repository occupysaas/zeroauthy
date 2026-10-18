package server

import (
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// admin serves the console at /admin/ on the system host only (design
// §4.4): files under assets/ as they are, every other path as index.html
// so that the console's router can handle deep links after a reload.
type admin struct {
	files      fs.FS
	store      store.Store
	baseDomain string
}

func (a admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if res, ok := tenant.FromContext(r.Context()); !ok || !res.Tenant.Reserved || res.Tenant.Name != tenant.SystemName {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/admin" {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", a.csp(r))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")

	name := path.Clean(strings.TrimPrefix(r.URL.Path, "/admin/"))
	if strings.HasPrefix(name, "assets/") {
		if st, err := fs.Stat(a.files, name); err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		// Asset names carry a content hash.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeFileFS(w, r, a.files, name)
		return
	}
	index, err := fs.ReadFile(a.files, "index.html")
	if err != nil {
		http.Error(w, "the console is not built", http.StatusNotFound)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(index)
}

// csp allows the console's own files only, and API calls to its own
// origin and to the tenants' hosts.
func (a admin) csp(r *http.Request) string {
	connect := []string{"'self'"}
	if a.baseDomain != "" {
		connect = append(connect, "https://*."+tenant.NormalizeHost(a.baseDomain))
	}
	if all, err := a.store.Tenants().List(r.Context()); err == nil {
		for _, t := range all {
			for _, d := range t.Domains {
				if src := "https://" + d; !slices.Contains(connect, src) {
					connect = append(connect, src)
				}
			}
		}
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
		"connect-src " + strings.Join(connect, " ") + "; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
}
