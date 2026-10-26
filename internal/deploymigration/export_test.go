package deploymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadExportBoundaries(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "duplicate.yaml")
	if err := os.WriteFile(bad, []byte("clients:\n  - client_id: a\n    client_id: b\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(bad, "yaml"); err == nil {
		t.Fatal("duplicate YAML key accepted")
	}
	if _, err := LoadExport(dir, "json"); err == nil {
		t.Fatal("unsupported format accepted")
	}
	dupDir := filepath.Join(dir, "duplicate-json")
	if err := os.Mkdir(dupDir, 0700); err != nil {
		t.Fatal(err)
	}
	dupJSON := filepath.Join(dupDir, "clients.json")
	if err := os.WriteFile(dupJSON, []byte(`{"clients":[{"client_id":"a","client_id":"b"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(dupDir, "directory"); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	parent := filepath.Join(dir, "parent.yaml")
	if err := os.WriteFile(parent, []byte("clients:\n  - client_id: a\n    config_file: file://../outside.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(parent, "yaml"); err == nil {
		t.Fatal("parent file reference accepted")
	}
	local := filepath.Join(dir, "local.yaml")
	if err := os.WriteFile(local, []byte("clients:\n  - client_id: a\n    config_file: file://configs/client.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "configs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "configs", "client.json"), []byte(`{"x":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExport(local, "yaml")
	if err != nil {
		t.Fatalf("safe relative reference rejected: %v", err)
	}
	if string(loaded.Files["configs/client.json"]) != `{"x":1}` {
		t.Fatal("referenced file was not hashed as input data")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "configs", "escape.json")); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(dir, "escape.yaml")
	if err := os.WriteFile(escape, []byte("clients:\n  - client_id: a\n    config_file: file://configs/escape.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(escape, "yaml"); err == nil {
		t.Fatal("symlink escape reference accepted")
	}

	// Script payloads are retained as bytes and are never evaluated.
	scriptRoot := filepath.Join(dir, "script-export")
	script := filepath.Join(scriptRoot, "scripts", "seed.js")
	if err := os.MkdirAll(filepath.Dir(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("throw new Error('must remain inert')"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadExport(scriptRoot, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Files["scripts/seed.js"]) != "throw new Error('must remain inert')" {
		t.Fatal("script payload was not preserved inertly")
	}
}

func TestLoadDirectoryMapsDeployCliGrantsFolder(t *testing.T) {
	root := t.TempDir()
	grants := filepath.Join(root, "grants")
	if err := os.Mkdir(grants, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(grants, "fixture.json"), []byte(`{"client_id":"app","audience":"https://api.test","scope":["read"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	export, err := LoadExport(root, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(export.Resources["clientGrants"]); got != `[{"audience":"https://api.test","client_id":"app","scope":["read"]}]` {
		t.Fatalf("client grant folder was not mapped: %s", got)
	}
}

func TestLoadDirectoryMapsEmailProviderAndTemplates(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"emails/provider.json":     `{"name":"smtp","enabled":false,"default_from_address":"mail@example.test"}`,
		"emails/verify_email.json": `{"template":"verify_email","enabled":true,"subject":"Verify","body":"Hello"}`,
		"emails/verify_email.html": `Hello`,
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	export, err := LoadExport(root, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(export.Resources["emailProvider"]); got != `[{"default_from_address":"mail@example.test","enabled":false,"name":"smtp"}]` {
		t.Fatalf("provider mapping = %s", got)
	}
	if got := string(export.Resources["emailTemplates"]); got != `[{"body":"Hello","enabled":true,"subject":"Verify","template":"verify_email"}]` {
		t.Fatalf("template mapping = %s", got)
	}
	if got := string(export.Files["emails/verify_email.html"]); got != "Hello" {
		t.Fatalf("template HTML export file = %q", got)
	}
}

func TestLoadExportRejectsAmbiguousClientIdentities(t *testing.T) {
	for _, clients := range []string{
		`[{"client_id":"one","name":"App"},{"client_id":"two","name":"App"}]`,
		`[{"client_id":"one","name":"App"},{"client_id":"one","name":"Other"}]`,
	} {
		file := filepath.Join(t.TempDir(), "tenant.yaml")
		if err := os.WriteFile(file, []byte("clients: "+clients), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadExport(file, "yaml"); err == nil {
			t.Fatal("ambiguous client identity accepted")
		}
	}
}

func TestLoadDirectoryBrandingPromptsAndThemes(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"branding/templates/universal-login.json":               `{"template":"universal-login","body":"./universal-login.html"}`,
		"branding/templates/universal-login.html":               `<p>Template bytes</p>`,
		"branding/branding.json":                                `{"colors":{"primary":"#123456"}}`,
		"themes/theme.json":                                     `{"themeId":"old","displayName":"Example","colors":{"primary_button":"#123456"}}`,
		"prompts/prompts.json":                                  `{"identifier_first":true}`,
		"prompts/custom-text.json":                              `{"en":{"login":{"login":{"title":"Example"}}}}`,
		"prompts/partials.json":                                 `{"login":[{"login":[{"name":"form-footer-start","template":"partials/login/login/form-footer-start.liquid"}]}]}`,
		"prompts/partials/login/login/form-footer-start.liquid": `<p>Example footer</p>`,
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := LoadExport(root, "directory")
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"branding", "themes", "prompts"} {
		if len(out.Resources[resource]) == 0 {
			t.Fatalf("missing %s", resource)
		}
	}
	if !strings.Contains(string(out.Resources["branding"]), `"templates"`) || !strings.Contains(string(out.Resources["branding"]), `"colors"`) {
		t.Fatalf("lost branding section: %s", out.Resources["branding"])
	}
	for _, key := range []string{"identifier_first", "customText", "partials"} {
		if !strings.Contains(string(out.Resources["prompts"]), `"`+key+`"`) {
			t.Fatalf("lost prompt section %s: %s", key, out.Resources["prompts"])
		}
	}
	if string(out.Files["prompts/partials/login/login/form-footer-start.liquid"]) != "<p>Example footer</p>" {
		t.Fatal("lost Liquid file")
	}
}

func TestDirectoryCustomDomains(t *testing.T) {
	for _, folder := range []string{"customDomains", "custom-domains", "custom_domains"} {
		t.Run(folder, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, folder), 0700); err != nil {
				t.Fatal(err)
			}
			body := `{"domain":"login.example.test","type":"self_managed_certs","custom_client_ip_header":null,"domain_metadata":{"brand":"example"},"is_default":true}`
			if err := os.WriteFile(filepath.Join(dir, folder, "login.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			export, err := LoadExport(dir, "directory")
			if err != nil {
				t.Fatal(err)
			}
			var want, got []map[string]any
			json.Unmarshal([]byte("["+body+"]"), &want)
			json.Unmarshal(export.Resources["customDomains"], &got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("custom domain not parsed as a resource: %s", export.Resources["customDomains"])
			}
			if len(export.Files) != 0 {
				t.Fatal("custom domain treated as an opaque file")
			}
		})
	}
}

func TestBrandingTemplateBodyReferences(t *testing.T) {
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			folder := "branding_templates"
			input := filepath.Join(dir, "tenant.yaml")
			if format == "directory" {
				folder = "branding/templates"
				input = dir
			}
			if err := os.MkdirAll(filepath.Join(dir, folder), 0700); err != nil {
				t.Fatal(err)
			}
			bodyFile := filepath.Join(dir, folder, "universal_login.html")
			if err := os.WriteFile(bodyFile, []byte("<p>Original template</p>"), 0600); err != nil {
				t.Fatal(err)
			}
			if format == "yaml" {
				os.WriteFile(input, []byte("branding:\n  templates:\n    - template: universal_login\n      body: ./branding_templates/universal_login.html\n"), 0600)
			} else {
				os.WriteFile(filepath.Join(dir, folder, "universal_login.json"), []byte(`{"template":"universal_login","body":"./universal_login.html"}`), 0600)
			}
			first, err := LoadExport(input, format)
			if err != nil {
				t.Fatal(err)
			}
			key := folder + "/universal_login.html"
			if string(first.Files[key]) != "<p>Original template</p>" {
				t.Fatal("actual CLI template body bytes missing")
			}
			os.WriteFile(bodyFile, []byte("<p>Changed template</p>"), 0600)
			changed, err := LoadExport(input, format)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(first.Files, changed.Files) {
				t.Fatal("changed template body invisible")
			}
			os.Remove(bodyFile)
			if _, err := LoadExport(input, format); err == nil {
				t.Fatal("missing template body accepted")
			}
		})
	}
}

func TestDirectoryCustomDomainCollectionFile(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "custom-domains")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	body := `[{"domain":"login.example.test","type":"self_managed_certs"},{"domain":"second.example.test","type":"auth0_managed_certs"}]`
	if err := os.WriteFile(filepath.Join(folder, "custom-domains.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	export, err := LoadExport(dir, "directory")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(export.Resources["customDomains"], &rows); err != nil || len(rows) != 2 {
		t.Fatalf("pinned CLI collection incorrectly nested: %s %v", export.Resources["customDomains"], err)
	}
}
