package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/go-viper/mapstructure/v2"
)

// TestReferenceUpToDate keeps docs/configuration.md in step with the
// Config struct and its comments, even where go generate was not run.
func TestReferenceUpToDate(t *testing.T) {
	want, err := Reference(".")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(ReferencePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("docs/configuration.md is out of date; run go generate ./internal/config")
	}
}

var referenceRow = regexp.MustCompile("(?m)^\\| `([a-z0-9_.]+)` \\| `([A-Z0-9_]+)` \\| ([^|]+) \\| (.*) \\|$")

// TestReferenceListsEveryKey decodes the documented keys into Config with
// the loader's decoder: ErrorUnset fails on any setting the page leaves out,
// ErrorUnused on any key the page invents.
func TestReferenceListsEveryKey(t *testing.T) {
	b, err := Reference(".")
	if err != nil {
		t.Fatal(err)
	}
	rows := referenceRow.FindAllStringSubmatch(string(b), -1)
	if len(rows) < 80 {
		t.Fatalf("only %d rows in the reference", len(rows))
	}
	var keys []string
	for _, row := range rows {
		key, env := row[1], row[2]
		if wantEnv := "ZEROAUTHY_" + strings.ToUpper(strings.ReplaceAll(key, ".", "__")); env != wantEnv {
			t.Errorf("%s: environment variable %s, want %s", key, env, wantEnv)
		}
		keys = append(keys, key)
	}
	if err := decodeKeys(keys); err != nil {
		t.Fatalf("reference and Config disagree: %v", err)
	}
	// The check itself must notice a missing and an invented key.
	if err := decodeKeys(keys[1:]); err == nil || !strings.Contains(err.Error(), "unset") {
		t.Errorf("dropping %s went unnoticed: %v", keys[0], err)
	}
	if err := decodeKeys(append(keys, "server.no_such_key")); err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("an invented key went unnoticed: %v", err)
	}
}

// decodeKeys decodes the dotted keys (all nil) into a Config.
func decodeKeys(keys []string) error {
	tree := map[string]any{}
	for _, key := range keys {
		parts := strings.Split(key, ".")
		m := tree
		for _, p := range parts[:len(parts)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		if _, dup := m[parts[len(parts)-1]]; dup {
			return fmt.Errorf("%s is listed twice", key)
		}
		m[parts[len(parts)-1]] = nil
	}
	var cfg Config
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "koanf", Result: &cfg, ErrorUnused: true, ErrorUnset: true,
	})
	if err != nil {
		return err
	}
	err = dec.Decode(tree)
	if err == nil {
		return nil
	}
	// mapstructure counts koanf:"-" fields (set by Load, never read) as a
	// field named "-"; only real names count.
	var real []string
	for line := range strings.SplitSeq(err.Error(), "\n") {
		_, fields, ok := strings.Cut(line, "has unset fields: ")
		if !ok {
			if strings.HasPrefix(line, "'") || strings.Contains(line, "invalid key") {
				real = append(real, line)
			}
			continue
		}
		for f := range strings.SplitSeq(fields, ", ") {
			if f != "-" {
				real = append(real, line)
				break
			}
		}
	}
	if len(real) == 0 {
		return nil
	}
	return errors.New(strings.Join(real, "\n"))
}

// TestReferenceEnvNamesLoad checks every documented variable is accepted by
// the real loader (a misnamed one fails as an unknown key).
func TestReferenceEnvNamesLoad(t *testing.T) {
	b, err := Reference(".")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost", "ZEROAUTHY_SERVER__NO_SUCH_KEY="}); err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Fatalf("an unknown variable is not reported as an invalid key: %v", err)
	}
	for _, row := range referenceRow.FindAllStringSubmatch(string(b), -1) {
		_, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost", row[2] + "="})
		if err != nil && strings.Contains(err.Error(), "invalid key") {
			t.Errorf("%s: %v", row[2], err)
		}
	}
}

// TestReferenceHidesSecrets: secret keys are marked and never show a value.
func TestReferenceHidesSecrets(t *testing.T) {
	b, err := Reference(".")
	if err != nil {
		t.Fatal(err)
	}
	secret := map[string]bool{}
	for _, row := range referenceRow.FindAllStringSubmatch(string(b), -1) {
		if strings.Contains(row[3], "**secret**") {
			secret[row[1]] = true
			if def, _, _ := strings.Cut(row[4], " | "); def != "—" && def != "(hidden)" {
				t.Errorf("%s shows a default: %s", row[1], def)
			}
		}
	}
	for _, k := range []string{"storage.dsn", "security.master_key", "email.smtp.password"} {
		if !secret[k] {
			t.Errorf("%s is not marked secret", k)
		}
	}
	if secret["security.master_key_file"] || secret["server.acme.hosted_wildcard.token_file"] {
		t.Error("file path keys are marked secret")
	}
	if got := defaultText(reflect.ValueOf("s3cr3t"), true); got != "(hidden)" {
		t.Errorf("secret default rendered as %q", got)
	}
}
