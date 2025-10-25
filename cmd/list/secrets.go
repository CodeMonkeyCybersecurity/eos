// cmd/list/secrets.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package list

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
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
		logger.Debug("Listing secrets for service", zap.String("service", service))

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

		// Build table data
		table := output.NewTable().
			WithHeaders("Service", "Secret Name", "Count")

		for _, secretName := range secretNames {
			table.AddRow(service, secretName, "1") // Count is always 1 per secret name
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
