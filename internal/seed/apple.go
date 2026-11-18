package seed

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

var appleEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolveAppleSecrets runs only on decoded seed input. Inline keys are never
// accepted; normalized in-memory seeds may subsequently be revalidated.
func resolveAppleSecrets(f *File, baseDir string) error {
	for i := range f.Tenants {
		for j := range f.Tenants[i].Connections {
			c := &f.Tenants[i].Connections[j]
			if c.Strategy != rules.Apple {
				continue
			}
			ref, ok := c.Options["app_secret"].(string)
			invalid := func() error {
				return errors.New("seed: apple options.app_secret requires a readable file://path or env://NAME reference containing a PKCS#8 PEM EC P-256 private key")
			}
			if !ok {
				return invalid()
			}
			var secret string
			switch {
			case strings.HasPrefix(ref, "env://"):
				name := strings.TrimPrefix(ref, "env://")
				if !appleEnvironmentName.MatchString(name) {
					return invalid()
				}
				secret = os.Getenv(name)
			case strings.HasPrefix(ref, "file://"):
				path := strings.TrimPrefix(ref, "file://")
				if path == "" || (!filepath.IsAbs(path) && baseDir == "") {
					return invalid()
				}
				if !filepath.IsAbs(path) {
					path = filepath.Join(baseDir, path)
				}
				// Bound the read like shared key validation, including oversized files.
				file, err := os.Open(path)
				if err != nil {
					return invalid()
				}
				data, readErr := io.ReadAll(io.LimitReader(file, 65537))
				_ = file.Close()
				if readErr != nil || len(data) > 65536 {
					return invalid()
				}
				secret = string(data)
			default:
				return invalid()
			}
			if _, err := rules.ParseAppleSigningKey(secret); err != nil {
				return invalid()
			}
			c.Options["app_secret"] = secret
		}
	}
	return nil
}
