// Package deploymigration reads untrusted Auth0 Deploy CLI exports and
// prepares an offline, credential-preserving bootstrap.
package deploymigration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Export struct {
	Resources map[string]json.RawMessage
	Files     map[string][]byte
}

// LoadExport parses either a single YAML export or a directory export. It
// preserves resource JSON and script bytes as inert data; no script is run.
func LoadExport(path, format string) (Export, error) {
	out := Export{Resources: map[string]json.RawMessage{}, Files: map[string][]byte{}}
	switch format {
	case "yaml":
		b, err := os.ReadFile(path)
		if err != nil {
			return Export{}, errors.New("deploymigration: cannot read YAML export")
		}
		v, err := parseYAML(b)
		if err != nil {
			return Export{}, errors.New("deploymigration: invalid YAML export")
		}
		if err := checkExportReferences(v, filepath.Dir(path), out.Files); err != nil {
			return Export{}, err
		}
		root, ok := v.(map[string]any)
		if !ok {
			return Export{}, errors.New("deploymigration: YAML export root must be an object")
		}
		if branding, ok := root["branding"].(map[string]any); ok {
			if templates, ok := branding["templates"].([]any); ok {
				for _, definition := range templates {
					if err := checkTemplateBodyReference(definition, filepath.Dir(path), "", out.Files); err != nil {
						return Export{}, err
					}
				}
			}
		}
		for name, value := range root {
			raw, err := json.Marshal(value)
			if err != nil {
				return Export{}, errors.New("deploymigration: invalid YAML resource")
			}
			out.Resources[name] = raw
		}
	case "directory":
		root, err := filepath.Abs(path)
		if err != nil {
			return Export{}, errors.New("deploymigration: invalid directory path")
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return Export{}, errors.New("deploymigration: directory export is unavailable")
		}
		groups := map[string][]json.RawMessage{}
		prompts := map[string]any{}
		var brandingTemplates []any
		err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("deploymigration: unreadable directory export")
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("deploymigration: symlinks are not allowed in directory exports")
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return errors.New("deploymigration: invalid export path")
			}
			rel = filepath.ToSlash(rel)
			b, err := os.ReadFile(p)
			if err != nil {
				return errors.New("deploymigration: unreadable export file")
			}
			ext := strings.ToLower(filepath.Ext(rel))
			if ext != ".json" && ext != ".yaml" && ext != ".yml" {
				out.Files[rel] = b
				return nil
			}
			var value any
			if ext == ".json" {
				if err := validateJSONNoDuplicates(b); err != nil {
					return errors.New("deploymigration: invalid JSON resource")
				}
				if err := json.Unmarshal(b, &value); err != nil {
					return errors.New("deploymigration: invalid JSON resource")
				}
			} else {
				value, err = parseYAML(b)
				if err != nil {
					return errors.New("deploymigration: invalid YAML resource")
				}
			}
			if err := checkExportReferences(value, root, out.Files); err != nil {
				return err
			}
			if strings.HasPrefix(rel, "branding/templates/") {
				if err := checkTemplateBodyReference(value, root, filepath.Dir(rel), out.Files); err != nil {
					return err
				}
				brandingTemplates = append(brandingTemplates, value)
				return nil
			}
			if strings.HasPrefix(rel, "prompts/") {
				switch rel {
				case "prompts/prompts.json":
					settings, ok := value.(map[string]any)
					if !ok {
						return errors.New("deploymigration: invalid prompt settings")
					}
					for key, field := range settings {
						prompts[key] = field
					}
				case "prompts/custom-text.json":
					prompts["customText"] = value
				case "prompts/partials.json":
					prompts["partials"] = value
				default:
					out.Files[rel] = b
				}
				return nil
			}
			name := resourceName(rel)
			if name == "" {
				out.Files[rel] = b
				return nil
			}
			if name == "customDomains" {
				if rows, ok := value.([]any); ok {
					for _, row := range rows {
						if _, ok := row.(map[string]any); !ok {
							return errors.New("deploymigration: invalid custom-domain collection")
						}
						raw, err := json.Marshal(row)
						if err != nil {
							return err
						}
						groups[name] = append(groups[name], raw)
					}
					return nil
				}
			}
			if name == "tenant" || name == "attackProtection" || name == "branding" || name == "triggers" {
				raw, err := json.Marshal(value)
				if err != nil {
					return err
				}
				out.Resources[name] = raw
				return nil
			}
			raw, err := json.Marshal(value)
			if err != nil {
				return errors.New("deploymigration: invalid resource data")
			}
			groups[name] = append(groups[name], raw)
			return nil
		})
		if err != nil {
			return Export{}, err
		}
		for name, rows := range groups {
			raw, _ := json.Marshal(rows)
			out.Resources[name] = raw
		}
		if len(prompts) > 0 {
			raw, _ := json.Marshal(prompts)
			out.Resources["prompts"] = raw
		}
		if len(brandingTemplates) > 0 {
			branding := map[string]any{}
			if raw := out.Resources["branding"]; len(raw) > 0 {
				if err := json.Unmarshal(raw, &branding); err != nil {
					return Export{}, errors.New("deploymigration: invalid branding settings")
				}
			}
			branding["templates"] = brandingTemplates
			raw, _ := json.Marshal(branding)
			out.Resources["branding"] = raw
		}
	default:
		return Export{}, errors.New("deploymigration: format must be yaml or directory")
	}
	if raw := out.Resources["clients"]; len(raw) > 0 {
		var rows []struct {
			ID   string `json:"client_id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return Export{}, errors.New("deploymigration: client collection must be an array")
		}
		ids, names := map[string]bool{}, map[string]bool{}
		for _, row := range rows {
			if (row.ID == "" && row.Name == "") || (row.ID != "" && ids[row.ID]) || (row.Name != "" && names[row.Name]) {
				return Export{}, errors.New("deploymigration: client identities are missing or ambiguous")
			}
			if row.ID != "" {
				ids[row.ID] = true
			}
			if row.Name != "" {
				names[row.Name] = true
			}
		}
	}
	return out, nil
}

func checkExportReferences(value any, root string, files map[string][]byte) error {
	var visit func(any, string) error
	visit = func(v any, key string) error {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if err := visit(child, k); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range x {
				if err := visit(child, key); err != nil {
					return err
				}
			}
		case string:
			// The pinned CLI exports this as inline JavaScript. Only an
			// explicit .js/file:// value is a materialized script reference.
			if key == "fetchUserProfile" && !isOAuthScriptReference(x) {
				return nil
			}
			p, isRef := x, false
			if strings.HasPrefix(strings.ToLower(x), "file://") {
				p, isRef = x[len("file://"):], true
			}
			if key == "code" && (strings.HasPrefix(x, "./") || strings.HasSuffix(x, ".js")) {
				isRef = true
			}
			if !isRef && (strings.Contains(strings.ToLower(key), "file") || strings.EqualFold(key, "path")) {
				isRef = true
			}
			if !isRef {
				return nil
			}
			p = filepath.FromSlash(p)
			clean := filepath.Clean(p)
			if p == "" || filepath.IsAbs(p) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return errors.New("deploymigration: absolute and parent file references are not allowed")
			}
			if root != "" {
				base, err := filepath.Abs(root)
				if err != nil {
					return errors.New("deploymigration: invalid export root")
				}
				target := filepath.Join(base, clean)
				rel, err := filepath.Rel(base, target)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return errors.New("deploymigration: file reference escapes export root")
				}
				cur := base
				for _, part := range strings.Split(rel, string(filepath.Separator)) {
					cur = filepath.Join(cur, part)
					info, statErr := os.Lstat(cur)
					if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
						return errors.New("deploymigration: referenced file is unavailable or unsafe")
					}
				}
				b, readErr := os.ReadFile(target)
				if readErr != nil {
					return errors.New("deploymigration: referenced file is unreadable")
				}
				files[filepath.ToSlash(clean)] = b
			}
		}
		return nil
	}
	return visit(value, "")
}

func resourceName(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	base := strings.TrimSuffix(parts[len(parts)-1], filepath.Ext(parts[len(parts)-1]))
	candidate := parts[0]
	if len(parts) > 1 && strings.EqualFold(parts[0], "emails") {
		if strings.EqualFold(base, "provider") {
			return "emailProvider"
		}
		return "emailTemplates"
	}
	if len(parts) == 1 {
		candidate = base
	}
	switch strings.ToLower(candidate) {
	case "actionmodules", "action-modules", "action_modules":
		return "actionModules"
	case "actions":
		return "actions"
	case "triggers":
		return "triggers"
	case "roles", "role":
		return "roles"
	case "clients", "client":
		return "clients"
	case "resourceservers", "resource-servers", "resource_servers":
		return "resourceServers"
	case "clientgrants", "client-grants", "client_grants":
		return "clientGrants"
	case "grants":
		// auth0-deploy-cli 9.1.0 stores client grants under grants/ in
		// directory exports, although the Management API family is clientGrants.
		return "clientGrants"
	case "customdomains", "custom-domains", "custom_domains":
		return "customDomains"
	case "connections", "connection":
		return "connections"
	case "databases", "database":
		return "databases"
	case "tenant":
		return "tenant"
	case "attackprotection", "attack-protection", "attack_protection":
		return "attackProtection"
	case "emailprovider", "email-provider", "email_provider":
		return "emailProvider"
	case "emailtemplates", "email-templates", "email_templates":
		return "emailTemplates"
	case "branding":
		return "branding"
	case "themes":
		return "themes"
	default:
		return ""
	}
}

func parseYAML(b []byte) (any, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		return nil, err
	}
	if err := checkYAMLKeys(&n); err != nil {
		return nil, err
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func checkYAMLKeys(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if seen[k.Value] {
				return errors.New("duplicate key")
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkYAMLKeys(c); err != nil {
			return err
		}
	}
	return nil
}

func validateJSONNoDuplicates(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := walkJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON member")
			}
			seen[key] = true
			if err := walkJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := walkJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

// The pinned Deploy CLI stores Universal Login template body as a relative
// HTML filename, not a file:// URL. YAML resolves it against the export root;
// directory exports resolve it beside the template definition JSON. Retain
// bytes in Files so strict comparisons detect changed or missing content.
func checkTemplateBodyReference(definition any, root, base string, files map[string][]byte) error {
	def, ok := definition.(map[string]any)
	if !ok {
		return errors.New("deploymigration: invalid branding template definition")
	}
	body, ok := def["body"].(string)
	if !ok {
		return errors.New("deploymigration: missing branding template body")
	}
	// Inline synthetic fixtures remain field-preserved; real CLI body paths
	// always begin ./ (or an explicit file:// reference).
	if !strings.HasPrefix(body, "./") && !strings.HasPrefix(body, "file://") && !strings.HasPrefix(body, "../") && !filepath.IsAbs(body) {
		return nil
	}
	body = strings.TrimPrefix(body, "file://")
	if filepath.IsAbs(body) {
		return errors.New("deploymigration: absolute template references are not allowed")
	}
	for _, part := range strings.Split(filepath.ToSlash(body), "/") {
		if part == ".." {
			return errors.New("deploymigration: parent template references are not allowed")
		}
	}
	rel := filepath.Join(base, filepath.FromSlash(body))
	return checkExportReferences(map[string]any{"body_file": rel}, root, files)
}
