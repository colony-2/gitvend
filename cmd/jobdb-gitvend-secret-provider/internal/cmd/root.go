// Package cmd defines the JobDB Gitvend provider's Cobra CLI.
package cmd

import (
	"fmt"

	"github.com/colony-2/gitvend/pkg/jobdbprovider"
	secretplugin "github.com/colony-2/jobdb/pkg/jobdb/secrets/plugin"
	"github.com/spf13/cobra"
)

const commandName = "jobdb-gitvend-secret-provider"

// Execute runs the command and returns an exit code. main prints any error once.
func Execute(version string) (int, error) {
	if err := newRootCmd(version).Execute(); err != nil {
		return 1, err
	}
	return 0, nil
}

func newRootCmd(version string) *cobra.Command {
	var path string
	root := &cobra.Command{
		Use:           commandName,
		Short:         "Issue lease-bound Gitvend JWTs as a JobDB secret-provider plugin",
		Long:          setupHelp,
		Example:       commandExamples,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("config") {
				return cmd.Help()
			}
			if path == "" {
				return fmt.Errorf("--config requires an issuer YAML file; use --help for setup instructions")
			}
			p, err := jobdbprovider.WatchConfig(path, func(message string) {
				fmt.Fprintln(cmd.ErrOrStderr(), commandName+":", message)
			})
			if err != nil {
				// Config parsing errors can contain credentials or arbitrary configuration.
				return fmt.Errorf("provider initialization failed; check the issuer YAML, signing key, and directory watch access; use --help for setup instructions")
			}
			defer p.Close()
			secretplugin.Serve(p)
			return nil
		},
	}
	root.Flags().StringVarP(&path, "config", "c", "", "Issuer YAML file to serve (required when launched by JobDB; signing-key paths are relative to this file)")
	_ = root.MarkFlagFilename("config", "yaml", "yml")
	root.AddCommand(newValidateCmd())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print build version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s version %s\n", commandName, version)
			return err
		},
	})
	return root
}

func newValidateCmd() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "validate",
		Short: "Validate issuer configuration and signing key without starting the plugin",
		Long: `Check the issuer YAML, tenant permission rules, token limits, and Ed25519
private key. Relative signing-key paths resolve from the issuer file's directory.
This does not start a file watcher, contact GitHub, or connect to a Gitvend gateway.
Run jobdb-gitvend-secret-provider --help for the complete setup instructions.`,
		Example: "  jobdb-gitvend-secret-provider validate --config /absolute/path/gitvend-issuer.yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				return fmt.Errorf("--config requires an issuer YAML file")
			}
			if _, err := jobdbprovider.Load(path); err != nil {
				return fmt.Errorf("configuration validation failed; check the issuer YAML, tenant permissions, token limits, and signing key")
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Configuration and signing key are valid.")
			return err
		},
	}
	command.Flags().StringVarP(&path, "config", "c", "", "Issuer YAML file to validate")
	_ = command.MarkFlagRequired("config")
	_ = command.MarkFlagFilename("config", "yaml", "yml")
	return command
}
