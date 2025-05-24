package pandora

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// exportCmd represents the `eos pandora export` base command.
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export Pandora-related files like TLS certs",
}

var exportTLSCmd = &cobra.Command{
	Use:   "--tls-crt",
	Short: "Export Vault TLS certificate to a remote machine",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := zap.L()
		if !vault.TlsCert {
			return nil
		}
		if vault.User == "" || vault.Host == "" || vault.Path == "" {
			return fmt.Errorf("user, host, and path are required")
		}
		return vault.ExportTLSCert(vault.User, vault.Host, vault.Path, log)
	},
}

func init() {
	exportTLSCmd.Flags().StringVar(&vault.User, "user", "", "Remote SSH username (required)")
	exportTLSCmd.Flags().StringVar(&vault.Host, "host", "", "Remote hostname (required)")
	exportTLSCmd.Flags().StringVar(&vault.Path, "path", "", "Remote path (e.g. ~/Downloads)")
	exportTLSCmd.Flags().BoolVar(&vault.TlsCert, "tls-crt", false, "Export Vault TLS certificate")

	exportCmd.AddCommand(exportTLSCmd)
}
