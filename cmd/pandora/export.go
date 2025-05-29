package pandora

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
)

// exportCmd represents the `eos pandora export` base command.
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export Pandora-related files like TLS certs",
}

var exportTLSCertCmd = &cobra.Command{
	Use:   "tls-crt",
	Short: "Export the Vault TLS client certificate to a remote machine via SSH",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if vault.User == "" || vault.Host == "" || vault.Path == "" {
			return fmt.Errorf("user, host, and path are required")
		}

		certPath := os.Getenv("VAULT_CLIENT_CERT")
		if certPath == "" {
			return fmt.Errorf("VAULT_CLIENT_CERT env var not set; cannot locate TLS cert")
		}

		input := vault.TLSExportInput{
			User: vault.User,
			Host: vault.Host,
			Path: vault.Path,
		}
		return vault.ExportTLSCert(rc, input)
	}),
}

func init() {
	exportTLSCertCmd.Flags().StringVar(&vault.User, "user", "", "Remote SSH username (required)")
	exportTLSCertCmd.Flags().StringVar(&vault.Host, "host", "", "Remote hostname (required)")
	exportTLSCertCmd.Flags().StringVar(&vault.Path, "path", "", "Remote path (e.g. ~/Downloads)")

	exportCmd.AddCommand(exportTLSCertCmd)
}
