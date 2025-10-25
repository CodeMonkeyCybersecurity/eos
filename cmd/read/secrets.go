package read

import (
	"fmt"
	"os"
	"strings"

	consulenv "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
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
	cmd.Flags().String("environment", "", "Override environment (requires CONSUL_EMERGENCY_OVERRIDE=true)")
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

// resolveEnvironment resolves the environment using correct precedence: Consul authoritative, flag for emergency override.
// Implements fail-closed security: blocks operations when environment cannot be determined.
func resolveEnvironment(rc *eos_io.RuntimeContext, flagEnv string) (sharedvault.Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// 1. Check emergency override
	if os.Getenv("CONSUL_EMERGENCY_OVERRIDE") == "true" {
		if flagEnv == "" {
			return "", fmt.Errorf("CONSUL_EMERGENCY_OVERRIDE requires --environment flag\n\n" +
				"Emergency override allows bypassing Consul when it's unavailable.\n" +
				"You MUST specify --environment flag to use emergency override.\n\n" +
				"Example:\n" +
				"  CONSUL_EMERGENCY_OVERRIDE=true eos read secrets --consul --environment development --show")
		}

		// Validate emergency override environment
		if err := sharedvault.ValidateEnvironment(flagEnv); err != nil {
			return "", fmt.Errorf("invalid --environment flag: %w", err)
		}

		logger.Warn("Using emergency override - Consul bypassed",
			zap.String("environment", flagEnv),
			zap.String("reason", "CONSUL_EMERGENCY_OVERRIDE=true"),
			zap.String("audit", "emergency_override"))

		return sharedvault.Environment(flagEnv), nil
	}

	// 2. Query Consul (authoritative)
	consulEnv, err := consulenv.DiscoverFromConsul(rc)
	if err != nil {
		// FAIL-CLOSED: No fallback to development
		return "", fmt.Errorf("cannot determine environment from Consul: %w\n\n"+
			"Consul is the authoritative source for environment configuration.\n"+
			"This system fails-closed for security (no fallback to development).\n\n"+
			"Remediation:\n"+
			"1. Ensure Consul is running: systemctl status consul\n"+
			"2. Set environment: eos update consul --environment <env>\n"+
			"3. Emergency override (Consul unavailable): CONSUL_EMERGENCY_OVERRIDE=true eos read secrets --consul --environment <env> --show",
			err)
	}

	// 3. Verify flag matches Consul (if provided)
	if flagEnv != "" && flagEnv != string(consulEnv) {
		return "", fmt.Errorf("--environment flag (%s) does not match Consul environment (%s)\n\n"+
			"Consul is authoritative. The --environment flag is rejected when it conflicts.\n"+
			"This prevents accidental exposure of wrong environment secrets.\n\n"+
			"Choose ONE of:\n"+
			"1. Remove --environment flag to use Consul value: %s\n"+
			"2. Update Consul: eos update consul --environment %s\n"+
			"3. Emergency override (bypass Consul): CONSUL_EMERGENCY_OVERRIDE=true eos read secrets --consul --environment %s --show",
			flagEnv, consulEnv, consulEnv, flagEnv, flagEnv)
	}

	logger.Info("Using environment from Consul",
		zap.String("environment", string(consulEnv)),
		zap.String("source", "consul"),
		zap.String("audit", "environment_resolution"))

	return consulEnv, nil
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

	// ASSESS - Resolve environment (Consul authoritative, fail-closed)
	flagEnv, _ := cmd.Flags().GetString("environment")
	env, err := resolveEnvironment(rc, flagEnv)
	if err != nil {
		return err
	}

	logger.Info("Resolved environment",
		zap.String("environment", string(env)))

	// ASSESS - Initialize Vault client and secret manager
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w\n\n"+
			"Remediation:\n"+
			"  - Ensure Vault is running: systemctl status vault\n"+
			"  - Check Vault status: vault status\n"+
			"  - Ensure Vault agent is running: systemctl status vault-agent-eos", err)
	}

	secretMgr := vault.NewVaultSecretManager(rc, vaultClient)

	// INTERVENE - Process each service
	hasSecrets := false
	for _, serviceName := range services {
		logger.Debug("Reading secrets for service",
			zap.String("service", serviceName),
			zap.String("environment", string(env)))

		// Convert service name to Service type
		service := sharedvault.Service(serviceName)
		if err := sharedvault.ValidateService(serviceName); err != nil {
			logger.Warn("Skipping invalid service", zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Get service secrets
		secretsData, err := secretMgr.GetServiceSecrets(rc.Ctx, env, service)
		if err != nil {
			logger.Warn("Failed to get secrets for service",
				zap.String("service", serviceName),
				zap.String("environment", string(env)),
				zap.Error(err))
			continue
		}

		if len(secretsData) == 0 {
			logger.Info("No secrets found for service",
				zap.String("service", serviceName),
				zap.String("environment", string(env)))
			continue
		}

		hasSecrets = true

		// EVALUATE - Display header for this service
		logger.Info(fmt.Sprintf("\n%s SECRETS (%s):", strings.ToUpper(serviceName), strings.ToUpper(string(env))))
		logger.Info(fmt.Sprintf("Found %d secret(s) for service '%s' in environment '%s'",
			len(secretsData), serviceName, env))

		// Read and display each secret
		for secretName, secretValue := range secretsData {
			// Display secret name
			logger.Info(fmt.Sprintf("\n%s:", secretName))

			// Display value (redacted or plaintext based on --show flag)
			if !showPlaintext {
				logger.Info("  value: ***REDACTED*** (use --show to display)")
			} else {
				// Convert to string
				valueStr, ok := secretValue.(string)
				if !ok {
					valueStr = fmt.Sprintf("%v", secretValue)
				}
				logger.Info(fmt.Sprintf("  value: %q", valueStr))
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
