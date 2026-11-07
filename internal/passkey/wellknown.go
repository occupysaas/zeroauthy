package passkey

import (
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// mobileIdentifierUsable checks the identities used to publish native trust.
// Management accepts arbitrary strings; these files must contain usable IDs.
func mobileIdentifierUsable(value string, android bool) bool {
	if len(value) > 255 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i, c := range p {
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && !(android && c == '_') && !(!android && c == '-') {
				return false
			}
			if android && i == 0 && !letter {
				return false
			}
		}
	}
	return true
}
func teamUsable(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func fingerprint(s string) (string, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 32 {
		return "", false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return "", false
		}
	}
	b, err := hex.DecodeString(strings.Join(parts, ""))
	return strings.ToUpper(s), err == nil && len(b) == 32
}

// NativeOrigins retains the RP policy's exact origins while refusing Android
// identities whose permissively stored package name cannot be associated.
func NativeOrigins(r rpid.Result, c *store.Client) []string {
	if c == nil || c.Mobile == nil || c.Mobile.Android == nil || mobileIdentifierUsable(c.Mobile.Android.AppPackageName, true) {
		return rpid.NativeOrigins(r, c)
	}
	clone := *c
	mobile := *c.Mobile
	mobile.Android = nil
	clone.Mobile = &mobile
	return rpid.NativeOrigins(r, &clone)
}

// WellKnown serves native password credential associations only on verified
// custom domains and operator aliases. It never redirects or trusts the RP
// parent as the request host; customers serve parent-domain files themselves.
func (s *Service) WellKnown(w http.ResponseWriter, r *http.Request) {
	missing := func() { httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"}) }
	res, ok := tenant.FromContext(r.Context())
	if !ok || s == nil || res.Tenant == nil {
		missing()
		return
	}
	policy := s.RPID
	policy.Store = s.Store
	rp, err := policy.For(r.Context(), res)
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		missing()
		return
	}
	if err != nil {
		httpx.WriteError(w, 500, "server_error", "Unable to load associations")
		return
	}
	if !rp.Valid || rp.Kind == rpid.KindCanonical {
		missing()
		return
	}
	available, err := s.supported(r.Context())
	if err != nil {
		httpx.WriteError(w, 500, "server_error", "Unable to load associations")
		return
	}
	if !available {
		missing()
		return
	}
	clients, _, err := s.Store.Clients().List(r.Context(), res.Tenant.ID, store.ClientFilter{}, store.Page{})
	if err != nil {
		httpx.WriteError(w, 500, "server_error", "Unable to load associations")
		return
	}
	slices.SortFunc(clients, func(a, b *store.Client) int { return strings.Compare(a.ClientID, b.ClientID) })
	apps := []string{}
	statements := []map[string]any{}
	for _, c := range clients {
		if !c.IsFirstParty || !slices.Contains(c.GrantTypes, clientrules.GrantPasskey) || c.Mobile == nil {
			continue
		}
		if ios := c.Mobile.IOS; ios != nil && teamUsable(ios.TeamID) && mobileIdentifierUsable(ios.AppBundleIdentifier, false) {
			id := ios.TeamID + "." + ios.AppBundleIdentifier
			if !slices.Contains(apps, id) {
				apps = append(apps, id)
			}
		}
		if a := c.Mobile.Android; a != nil && mobileIdentifierUsable(a.AppPackageName, true) {
			fps := []string{}
			for _, fp := range a.SHA256CertFingerprints {
				if v, ok := fingerprint(fp); ok && !slices.Contains(fps, v) {
					fps = append(fps, v)
				}
			}
			if len(fps) > 0 {
				statements = append(statements, map[string]any{"relation": []string{"delegate_permission/common.get_login_creds"}, "target": map[string]any{"namespace": "android_app", "package_name": a.AppPackageName, "sha256_cert_fingerprints": fps}})
			}
		}
	}
	var body any
	switch r.URL.Path {
	case "/.well-known/apple-app-site-association":
		if len(apps) == 0 {
			missing()
			return
		}
		body = map[string]any{"webcredentials": map[string]any{"apps": apps}}
	case "/.well-known/assetlinks.json":
		if len(statements) == 0 {
			missing()
			return
		}
		body = statements
	default:
		missing()
		return
	}
	w.Header().Set("Cache-Control", "max-age=300")
	httpx.WriteJSON(w, 200, body)
}
