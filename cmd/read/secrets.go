package read

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// readSecretsCmd is the top-level 'eos pandora inspect' command.
var readSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Inspect secrets and data in Pandora (Vault)",
	Long:  "Inspect and view stored secrets or test data in Pandora (Vault).",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

// exportCmd represents the `eos pandora export` base command.
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export Pandora-related files like TLS certs",
}

var exportTLSCertCmd = &cobra.Command{
	Use:   "tls-crt",
	Short: "Export the Vault TLS client certificate to a remote machine via SSH",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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

// InspectTestDataCmd attempts to read test data from Vault,
// falling back to disk if Vault is unavailable.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test-data from Vault (fallback to disk)",
	Long:  `Reads and displays the test-data stored in Vault, or falls back to local disk.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		var client *vaultapi.Client
		var out map[string]interface{}
		var vaultReadErr error

		client, err := vault.Authn(rc)
		if err != nil {
			log.Warn("Vault auth failed, falling back to disk", zap.Error(err))
			client = nil // triggers fallback to disk
		}

		if client != nil {
			log.Info(" Attempting to read test-data from Vault...")
			if err := vault.Read(rc, client, shared.TestDataVaultPath, &out); err != nil {
				vaultReadErr = err
				if vault.IsSecretNotFound(err) {
					log.Warn("Test-data not found in Vault, attempting disk fallback...", zap.Error(err))
				} else {
					log.Error(" Vault read error", zap.String("vault_path", shared.TestDataVaultPath), zap.Error(err))
					return fmt.Errorf("vault read failed at '%s': %w", shared.TestDataVaultPath, err)
				}
			}
		}

		// If Vault read succeeded
		if vaultReadErr == nil && client != nil {
			vault.PrintData(rc, out, "Vault", "secret/data/"+shared.TestDataVaultPath)
			log.Info(" Test-data read successfully from Vault")
			return nil
		}

		// Otherwise fallback to disk
		log.Info(" Attempting fallback to disk...")

		if fallbackErr := vault.InspectFromDisk(rc); fallbackErr != nil {
			log.Error(" Both Vault and disk fallback failed",
				zap.String("vault_path", shared.TestDataVaultPath),
				zap.Error(vaultReadErr),
				zap.Error(fallbackErr),
			)
			return fmt.Errorf(
				"vault read failed at '%s' (%v); disk fallback also failed (%v)",
				shared.TestDataVaultPath, vaultReadErr, fallbackErr,
			)
		}

		log.Info(" Test-data read successfully from fallback")
		return nil
	}),
}

func init() {
	readSecretsCmd.AddCommand(InspectTestDataCmd)
}
