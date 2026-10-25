package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func newMigrationCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "migration", Short: "Prepare and apply deployment migrations", Args: cobra.NoArgs}
	cmd.AddCommand(newMigrationBootstrapCmd())
	return cmd
}

func newMigrationBootstrapCmd() *cobra.Command {
	var configPath, input, format, bootstrapPath, credentialsPath string
	var excluded []string
	var check bool
	cmd := &cobra.Command{Use: "bootstrap", Short: "Create a fresh destination while preserving source client credentials", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return errors.New("migration bootstrap: invalid configuration")
			}
			if cfg.SeedMode != string(seed.ModeCreateOnly) {
				return errors.New("migration bootstrap requires seed_mode: create_only")
			}
			if discardsData(cfg.Storage.DSN) || strings.HasPrefix(cfg.Storage.DSN, "memory:") {
				return errors.New("migration bootstrap refuses ephemeral memory storage")
			}
			credentials, err := readCredentialFile(credentialsPath)
			if err != nil {
				return err
			}
			export, err := deploymigration.LoadExport(input, format)
			if err != nil {
				return err
			}
			if raw := export.Resources["resourceServers"]; len(raw) > 0 {
				var resources []json.RawMessage
				if err := json.Unmarshal(raw, &resources); err != nil {
					return errors.New("migration bootstrap: invalid API inventory")
				}
				if err := deploymigration.CheckExportInventory(resources); err != nil {
					return err
				}
			}
			bootstrap, err := seed.Load(bootstrapPath)
			if err != nil {
				return errors.New("migration bootstrap: invalid local bootstrap seed")
			}
			if len(bootstrap.Tenants) != 1 {
				return errors.New("migration bootstrap: local seed must define one destination tenant")
			}
			if err := bootstrap.CheckSystemHost(tenant.SystemHost(cfg.Server.BaseDomain, cfg.Server.SystemHost)); err != nil {
				return errors.New("migration bootstrap: local seed conflicts with system host")
			}
			if err := bootstrap.CheckManagementAPI(cfg.Server.BaseDomain); err != nil {
				return errors.New("migration bootstrap: invalid local Management API grant")
			}
			prepared, err := deploymigration.PrepareBootstrap(export, bootstrap, credentials, deploymigration.BootstrapOptions{ExcludedClientIDs: excluded})
			if err != nil {
				return err
			}
			masterKey, err := app.MasterKey(cfg, nil)
			if err != nil {
				return errors.New("migration bootstrap: master key unavailable")
			}
			wrapper, err := keys.NewLocalWrapper(masterKey)
			if err != nil {
				return errors.New("migration bootstrap: master key unavailable")
			}
			st, err := storage.Open(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return errors.New("migration bootstrap: storage unavailable")
			}
			defer st.Close()
			if m, ok := st.(storage.Migrator); ok {
				if err := m.CheckSchema(cmd.Context()); err != nil {
					return errors.New("migration bootstrap: storage schema is not ready")
				}
			}
			var result deploymigration.BootstrapResult
			if check {
				result, err = deploymigration.CheckBootstrap(cmd.Context(), st, prepared, wrapper)
			} else {
				result, err = deploymigration.ApplyBootstrap(cmd.Context(), st, prepared, wrapper, nil)
			}
			if err != nil {
				return err
			}
			status := "ready"
			if result.AlreadyApplied {
				status = "already_applied"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "migration bootstrap: status=%s clients=%d\n", status, result.ClientCount)
			return err
		}}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to configuration")
	cmd.Flags().StringVar(&input, "input", "", "source deploy-cli export path")
	cmd.Flags().StringVar(&format, "format", "", "source format: yaml or directory")
	cmd.Flags().StringVar(&bootstrapPath, "bootstrap-seed", "", "protected local create-only bootstrap seed")
	cmd.Flags().StringVar(&credentialsPath, "credentials-file", "", "protected JSON mapping of source client IDs to secrets")
	cmd.Flags().StringSliceVar(&excluded, "exclude-client-id", nil, "source client ID omitted intentionally by the deploy tool (repeatable)")
	cmd.Flags().BoolVar(&check, "check", false, "preflight without writing")
	for _, name := range []string{"input", "format", "bootstrap-seed", "credentials-file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func readCredentialFile(path string) (map[string]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("migration bootstrap: credentials file is unavailable")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("migration bootstrap: credentials file permissions must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil || validateCredentialJSON(b) != nil {
		return nil, errors.New("migration bootstrap: credentials file must be a protected JSON object")
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil || out == nil {
		return nil, errors.New("migration bootstrap: credentials file must be a JSON object")
	}
	for id, secret := range out {
		if strings.TrimSpace(id) == "" || secret == "" {
			return nil, errors.New("migration bootstrap: credentials file contains an empty entry")
		}
	}
	return out, nil
}

func validateCredentialJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := walkCredentialJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkCredentialJSON(d *json.Decoder) error {
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
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if err := walkCredentialJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := walkCredentialJSON(d); err != nil {
				return err
			}
		}
		_, err := d.Token()
		return err
	default:
		return errors.New("invalid JSON")
	}
}
