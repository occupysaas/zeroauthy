package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func newAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Manage console operators",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newAdminCreateCmd())
	return cmd
}

func newAdminCreateCmd() *cobra.Command {
	var configPath, email string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a console operator and print a one-time setup link",
		Long: `Create a console operator in the system tenant and print a one-time link,
valid for one hour, where they choose a password. Running it again for the
same address prints a new link. It uses the server's storage (the same
config file), so only someone with access to it can create operators.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if email == "" {
				return errors.New("--email is required")
			}
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			masterKey, err := app.MasterKey(cfg, slog.Default())
			if err != nil {
				return err
			}
			wrapper, err := keys.NewLocalWrapper(masterKey)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			st, err := storage.Open(ctx, cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer st.Close()
			// Never write into a schema that is missing or from another version.
			if m, ok := st.(storage.Migrator); ok {
				if err := m.CheckSchema(ctx); err != nil {
					return err
				}
			}
			host := tenant.SystemHost(cfg.Server.BaseDomain, cfg.Server.SystemHost)
			if _, err := system.Ensure(ctx, st, system.Config{Host: host, Wrapper: wrapper}); err != nil {
				return err
			}
			link, err := system.CreateOperator(ctx, st, email)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "operator %s: open this link within 1 hour to choose a password:\n%s\n", email, link)
			if discardsData(cfg.Storage.DSN) {
				fmt.Fprintln(out, "note: memory storage is discarded when this command exits; the link will not work")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	cmd.Flags().StringVar(&email, "email", "", "the operator's email address")
	return cmd
}
