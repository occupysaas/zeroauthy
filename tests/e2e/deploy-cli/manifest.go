package main

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

type Manifest struct {
	ToolVersion    string             `json:"toolVersion"`
	Resources      []ManifestResource `json:"resources"`
	Normalizations []Normalization    `json:"normalizations"`
}
type ManifestResource struct {
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	Owner   string  `json:"owner"`
	Reason  string  `json:"reason"`
	Fixture *string `json:"fixture"`
}
type Normalization struct {
	Resource string `json:"resource"`
	Path     string `json:"path"`
	Rule     string `json:"rule"`
	Reason   string `json:"reason"`
}

func LoadManifest(path string) (Manifest, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Manifest{}, errors.New("manifest unavailable")
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil {
		return Manifest{}, errors.New("manifest invalid")
	}
	return m, nil
}
func ValidateManifest(m Manifest, registry []string) error {
	if m.ToolVersion == "" || len(m.Resources) == 0 {
		return errors.New("manifest missing version or handlers")
	}
	entries := map[string]ManifestResource{}
	for _, e := range m.Resources {
		if e.Name == "" || entries[e.Name].Name != "" {
			return errors.New("manifest has duplicate or empty handler")
		}
		if e.Status != "included" && e.Status != "excluded" && e.Status != "tool-unsupported" {
			return errors.New("manifest has invalid status")
		}
		if e.Reason == "" || e.Owner == "" {
			return errors.New("manifest entries require an owner and reason")
		}
		if e.Status == "included" && (e.Fixture == nil || strings.TrimSpace(*e.Fixture) == "") {
			return errors.New("included handlers require fixtures")
		}
		if e.Status != "included" && e.Fixture != nil {
			return errors.New("excluded handlers cannot claim fixtures")
		}
		if e.Status == "excluded" && !strings.HasPrefix(e.Owner, "Plan ") && !strings.HasPrefix(e.Owner, "roadmap:") {
			return errors.New("excluded handler has no roadmap owner")
		}
		entries[e.Name] = e
	}
	reg := map[string]bool{}
	for _, n := range registry {
		if n == "" || reg[n] {
			return errors.New("registry has duplicate or empty handler")
		}
		reg[n] = true
	}
	if len(reg) != len(entries) {
		return errors.New("manifest coverage differs from registry")
	}
	for n := range reg {
		if _, ok := entries[n]; !ok {
			return errors.New("manifest omits a registered handler")
		}
	}
	allowed := map[string]string{
		"clients.client_id": "reference-map", "clients.client_secret": "secret-bootstrap-or-omitted", "clients.created_at": "read-only", "clients.updated_at": "read-only",
		"resourceServers.id": "reference-map", "resourceServers.client_id": "read-only", "resourceServers.is_system": "system-exclusion",
		"clientGrants.id": "reference-map", "clientGrants.client_id": "reference-map", "clientGrants.audience": "reference-map",
		"connections.id": "reference-map", "connections.enabled_clients[].client_id": "reference-map",
		"databases.id": "reference-map", "databases.enabled_clients[].client_id": "reference-map",
		"actionModules.latest_version_number": "read-only",
		"themes.themeId":                      "reference-map",
		"customDomains.custom_domain_id":      "read-only", "customDomains.verification": "read-only", "customDomains.status": "read-only", "customDomains.origin_domain_name": "read-only", "customDomains.certificate": "read-only",
		"tenant.updated_at": "read-only", "tenant.default_audience": "tenant-url", "attackProtection.updated_at": "read-only",
	}
	for _, n := range m.Normalizations {
		e, ok := entries[n.Resource]
		if !ok || e.Status != "included" || n.Path == "" || n.Rule == "" || n.Reason == "" {
			return errors.New("normalization references an invalid resource or path")
		}
		if strings.Contains(n.Path, "*") || strings.HasPrefix(n.Path, ".") || strings.Contains(n.Path, "..") {
			return errors.New("normalization path is not field-specific")
		}
		if allowed[n.Resource+"."+n.Path] != n.Rule {
			return errors.New("normalization is outside its approved resource fields")
		}
		switch n.Rule {
		case "reference-map", "secret-bootstrap-or-omitted", "read-only", "system-exclusion", "tenant-url":
		default:
			return errors.New("manifest normalization rule is unsupported")
		}
	}
	return nil
}
func Exclusions(m Manifest) []string {
	out := []string{}
	for _, e := range m.Resources {
		if e.Status == "excluded" || e.Status == "tool-unsupported" {
			out = append(out, e.Name)
		}
	}
	sort.Strings(out)
	return out
}
func PreflightInventory(raw []byte) error {
	var resources []json.RawMessage
	if json.Unmarshal(raw, &resources) != nil {
		return errors.New("invalid API inventory")
	}
	return deploymigration.CheckExportInventory(resources)
}
