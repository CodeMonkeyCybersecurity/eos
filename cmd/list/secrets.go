// cmd/list/secrets.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package list

import (
	"fmt"
	"os"
	"strings"

	consulenv "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Available services for secret management
var availableServices = []string{
	"consul",
	"authentik",
	"bionicgpt",
	"wazuh",
}

var listSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List secrets and metadata for specified service(s)",
	Long: `List secrets stored in Vault for specified service(s) with metadata.

This command displays secret names and basic metadata (version, timestamps)
without revealing the actual secret values. Use 'eos read secrets' to view
secret values.

EXAMPLES:
  # List Consul secrets
  eos list secrets --consul

  # List Authentik secrets
  eos list secrets --authentik

  # List all secrets across all services
  eos list secrets --all

SECURITY:
  This command only displays metadata, never secret values.`,

	RunE: eos_cli.Wrap(runListSecrets),
}

func init() {
	addServiceFlagsToList(listSecretsCmd)
	ListCmd.AddCommand(listSecretsCmd)
}

// addServiceFlagsToList adds mutually exclusive service selector flags
func addServiceFlagsToList(cmd *cobra.Command) {
	cmd.Flags().Bool("consul", false, "List Consul secrets")
	cmd.Flags().Bool("authentik", false, "List Authentik secrets")
	cmd.Flags().Bool("bionicgpt", false, "List BionicGPT secrets")
	cmd.Flags().Bool("wazuh", false, "List Wazuh secrets")
	cmd.Flags().Bool("all", false, "List secrets for all services")
	cmd.Flags().String("environment", "", "Override environment (requires CONSUL_EMERGENCY_OVERRIDE=true)")
	cmd.MarkFlagsMutuallyExclusive("consul", "authentik", "bionicgpt", "wazuh", "all")
}

// getSelectedServicesForList returns list of services to target based on flags
func getSelectedServicesForList(cmd *cobra.Command) ([]string, error) {
	var selected []string

	// Check each service flag
	for _, svc := range availableServices {
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
		return availableServices, nil
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("must specify a service (--consul, --authentik, --bionicgpt, --wazuh) or --all\n" +
			"Example: eos list secrets --consul")
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
				"  CONSUL_EMERGENCY_OVERRIDE=true eos list secrets --consul --environment development")
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
			"3. Emergency override (Consul unavailable): CONSUL_EMERGENCY_OVERRIDE=true eos list secrets --consul --environment <env>",
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
			"3. Emergency override (bypass Consul): CONSUL_EMERGENCY_OVERRIDE=true eos list secrets --consul --environment %s",
			flagEnv, consulEnv, consulEnv, flagEnv, flagEnv)
	}

	logger.Info("Using environment from Consul",
		zap.String("environment", string(consulEnv)),
		zap.String("source", "consul"),
		zap.String("audit", "environment_resolution"))

	return consulEnv, nil
}

// runListSecrets orchestrates secret listing with metadata display.
// Follows Assess → Intervene → Evaluate pattern.
func runListSecrets(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get selected services
	services, err := getSelectedServicesForList(cmd)
	if err != nil {
		logger.Error("Invalid service selection", zap.Error(err))
		return err
	}

	logger.Info("Listing secrets", zap.Strings("services", services))

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
		logger.Debug("Listing secrets for service",
			zap.String("service", serviceName),
			zap.String("environment", string(env)))

		// Convert service name to Service type
		service := sharedvault.Service(serviceName)
		if err := sharedvault.ValidateService(serviceName); err != nil {
			logger.Warn("Skipping invalid service", zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Get service metadata
		metadata, err := secretMgr.GetServiceMetadata(rc.Ctx, env, service)
		if err != nil {
			logger.Warn("Failed to get metadata for service",
				zap.String("service", serviceName),
				zap.String("environment", string(env)),
				zap.Error(err))
			continue
		}

		if len(metadata.Keys) == 0 {
			logger.Info("No secrets found for service",
				zap.String("service", serviceName),
				zap.String("environment", string(env)))
			continue
		}

		hasSecrets = true

		// EVALUATE - Display header for this service
		logger.Info(fmt.Sprintf("\n%s SECRETS (%s):", strings.ToUpper(serviceName), strings.ToUpper(string(env))))
		logger.Info(fmt.Sprintf("Found %d secret(s) for service '%s' in environment '%s'",
			len(metadata.Keys), serviceName, env))

		// Build table data
		table := output.NewTable().
			WithHeaders("Service", "Environment", "Secret Name", "Version")

		for _, secretName := range metadata.Keys {
			table.AddRow(
				serviceName,
				string(env),
				secretName,
				fmt.Sprintf("%d", metadata.CurrentVersion))
		}

		// Display table
		if err := table.Render(); err != nil {
			logger.Warn("Failed to render table", zap.Error(err))
		}
	}

	// EVALUATE - Final summary
	if !hasSecrets {
		logger.Info("No secrets found for any of the specified services")
		logger.Info("Tip: Use 'eos create <service>' to deploy services and generate secrets")
	} else {
		logger.Info("Secrets listing complete")
		logger.Info("Tip: Use 'eos read secrets --<service> --show' to view secret values")
	}

	return nil
}
