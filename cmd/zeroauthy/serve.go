package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/phone"
)

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			log := newLogger(cmd.ErrOrStderr(), cfg.Log)
			if cfg.TestPhone.Active() {
				phone.SetTestEndpoints(cfg.TestPhone.Twilio, cfg.TestPhone.SNS)
				log.Warn("ZA_TEST_PHONE_ENDPOINTS active: phone providers redirected to local fakes (test mode only)")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			a, err := app.New(ctx, cfg, log)
			if err != nil {
				return err
			}
			defer a.Close()
			return a.Serve(ctx)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	return cmd
}
