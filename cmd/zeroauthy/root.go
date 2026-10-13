// cmd/zeroauthy/root.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=<v>".
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "zeroauthy",
		Short:         "Auth0-compatible identity server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(), newServeCmd(), newSeedCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the zeroauthy version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "zeroauthy", version)
			return err
		},
	}
}
