package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/storage"
)

func newSeedCmd() *cobra.Command {
	var configPath, file string
	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Apply a declarative seed file to the configured store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			path := file
			if path == "" {
				path = cfg.Seed
			}
			if path == "" {
				return errors.New("no seed file: pass --file or set seed in the config")
			}
			f, err := seed.Load(path)
			if err != nil {
				return err
			}
			st, err := storage.Open(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer st.Close()
			if err := seed.Apply(cmd.Context(), st, f, time.Now); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied %s: %d tenant(s)\n", path, len(f.Tenants))
			if strings.HasPrefix(cfg.Storage.DSN, "memory:") {
				fmt.Fprintln(cmd.OutOrStdout(), "note: memory storage is discarded when this command exits; the seed was validated only")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	cmd.Flags().StringVarP(&file, "file", "f", "", "seed file (defaults to the config's seed setting)")
	return cmd
}
