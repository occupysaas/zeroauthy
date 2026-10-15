package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/storage"
)

func newMigrateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending storage migrations for the configured driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			st, err := storage.Open(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer st.Close()
			m, ok := st.(interface {
				storage.Migrator
				SchemaVersion(context.Context) (int64, error)
				LatestVersion() int64
			})
			if !ok {
				fmt.Fprintln(cmd.OutOrStdout(), "this storage driver has no schema; nothing to migrate")
				return nil
			}
			before, err := m.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			if err := m.Migrate(cmd.Context()); err != nil {
				return err
			}
			if before == m.LatestVersion() {
				fmt.Fprintf(cmd.OutOrStdout(), "schema is up to date (version %d)\n", before)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "migrated schema from version %d to %d\n", before, m.LatestVersion())
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	return cmd
}
