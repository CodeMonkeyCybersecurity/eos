package read

import (
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Available services for secret management
var availableServicesForRead = []string{
	"consul",
	"authentik",
	"bionicgpt",
	"wazuh",
}

// readSecretsCmd is the root command for reading secrets from Vault.
// It can read service-specific secrets with the --show flag for plaintext display.
// The 'test-data' subcommand is preserved for backward compatibility.
var readSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Read secrets from Vault",
	Long: `Read and display secret values from Vault for specified service(s).

By default, secret values are REDACTED for security. Use the --show flag
to display plaintext values.

EXAMPLES:
  # Read Consul secrets (redacted by default)
  eos read secrets --consul

  # Read Authentik secrets with plaintext values
  eos read secrets --authentik --show

  # Read all secrets (redacted)
  eos read secrets --all

SECURITY:
  Secret values are redacted by default. Use --show flag to display plaintext.

SUBCOMMANDS:
  test-data    Read test data from Vault (legacy command)`,

	RunE: eos.Wrap(runReadSecrets),
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
		var out map[string]any
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
	// Add service selector flags
	addServiceFlagsToRead(readSecretsCmd)

	// Add --show flag for plaintext display
	readSecretsCmd.Flags().Bool("show", false, "Display plaintext secret values (default: redacted)")

	// Keep existing test-data subcommand
	readSecretsCmd.AddCommand(InspectTestDataCmd)
}

// addServiceFlagsToRead adds mutually exclusive service selector flags
func addServiceFlagsToRead(cmd *cobra.Command) {
	cmd.Flags().Bool("consul", false, "Read Consul secrets")
	cmd.Flags().Bool("authentik", false, "Read Authentik secrets")
	cmd.Flags().Bool("bionicgpt", false, "Read BionicGPT secrets")
	cmd.Flags().Bool("wazuh", false, "Read Wazuh secrets")
	cmd.Flags().Bool("all", false, "Read secrets for all services")
	cmd.MarkFlagsMutuallyExclusive("consul", "authentik", "bionicgpt", "wazuh", "all")
}

// getSelectedServicesForRead returns list of services to target based on flags
func getSelectedServicesForRead(cmd *cobra.Command) ([]string, error) {
	var selected []string

	// Check each service flag
	for _, svc := range availableServicesForRead {
		if flagVal, _ := cmd.Flags().GetBool(svc); flagVal {
			selected = append(selected, svc)
		}
	}

	// Check --all flag
	allFlag, _ := cmd.Flags().GetBool("all")

	// Validation logic
	if allFlag {
		if len(selected) > 0 {
			return nil, fmt.Errorf("cannot use --all with specific service flags")
		}
		return availableServicesForRead, nil
	}

	if len(selected) == 0 {
		// No service flag specified - this is OK, show help
		return nil, nil
	}

	if len(selected) > 1 {
		return nil, fmt.Errorf("cannot specify multiple service flags (use --all for all services)")
	}

	return selected, nil
}

// runReadSecrets orchestrates secret reading with optional plaintext display.
// Follows Assess → Intervene → Evaluate pattern.
func runReadSecrets(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get selected services
	services, err := getSelectedServicesForRead(cmd)
	if err != nil {
		logger.Error("Invalid service selection", zap.Error(err))
		return err
	}

	// If no service selected, show help (allows subcommands to work)
	if services == nil {
		return cmd.Help()
	}

	// Get --show flag
	showPlaintext, _ := cmd.Flags().GetBool("show")

	if showPlaintext {
		logger.Warn("⚠️  WARNING: Displaying plaintext secret values")
		logger.Warn("Ensure your terminal is secure and no screen sharing is active")
	}

	logger.Info("Reading secrets", zap.Strings("services", services), zap.Bool("show_plaintext", showPlaintext))

	// ASSESS - Discover environment and initialize secret manager
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w\n"+
			"Fix: Ensure Vault or secret backend is properly configured", err)
	}

	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w\n"+
			"Fix: Ensure Vault is accessible and properly configured", err)
	}

	logger.Debug("Initialized secret manager",
		zap.String("environment", envConfig.Environment))

	// INTERVENE - Process each service
	hasSecrets := false
	for _, service := range services {
		logger.Debug("Reading secrets for service", zap.String("service", service))

		// List secrets for this service using SDK methods
		secretNames, err := secretManager.ListSecrets(service)
		if err != nil {
			logger.Error("Failed to list secrets",
				zap.String("service", service),
				zap.Error(err))
			return fmt.Errorf("failed to list secrets for service '%s': %w\n"+
				"Fix: Ensure service exists in Vault and has proper permissions", service, err)
		}

		if len(secretNames) == 0 {
			logger.Info("No secrets found for service", zap.String("service", service))
			continue
		}

		hasSecrets = true

		// EVALUATE - Display header for this service
		logger.Info(fmt.Sprintf("\n%s SECRETS:", strings.ToUpper(service)))
		logger.Info(fmt.Sprintf("Found %d secret(s) for service '%s'", len(secretNames), service))

		// Read and display each secret
		for _, secretName := range secretNames {
			// Get secret value using SDK methods
			secretValue, err := secretManager.GetSecret(service, secretName)
			if err != nil {
				logger.Warn("Failed to read secret",
					zap.String("service", service),
					zap.String("secret", secretName),
					zap.Error(err))
				logger.Info(fmt.Sprintf("\n%s: ERROR (failed to read)", secretName))
				continue
			}

			// Display secret name
			logger.Info(fmt.Sprintf("\n%s:", secretName))

			// Display value (redacted or plaintext based on --show flag)
			if !showPlaintext {
				logger.Info("  value: ***REDACTED*** (use --show to display)")
			} else {
				logger.Info(fmt.Sprintf("  value: %q", secretValue))
			}
		}
	}

	// EVALUATE - Final summary
	if !hasSecrets {
		logger.Info("No secrets found for any of the specified services")
		logger.Info("Tip: Use 'eos create <service>' to deploy services and generate secrets")
	} else {
		logger.Info("\nSecrets reading complete")
		if !showPlaintext {
			logger.Info("Tip: Use --show flag to display plaintext values")
		}
	}

	return nil
}
