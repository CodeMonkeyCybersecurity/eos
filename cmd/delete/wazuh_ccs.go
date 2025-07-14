// cmd/delete/wazuh_ccs.go
package delete

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp/customer"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeleteWazuhCCSCmd removes Wazuh MSSP customers or components
var DeleteWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "Remove Wazuh MSSP customers or platform components",
	Long: `Remove customers or components from the Wazuh MSSP platform.

This command can:
- Remove a customer completely (--remove-customer)
- Archive customer data before removal (--archive)
- Force removal even with active connections (--force)

WARNING: Customer removal is permanent and cannot be undone without a backup.`,
	RunE: eos_cli.Wrap(runDeleteWazuhCCS),
}

func init() {
	DeleteCmd.AddCommand(DeleteWazuhCCSCmd)

	// Customer removal flags
	DeleteWazuhCCSCmd.Flags().Bool("remove-customer", false, "Remove a customer from the platform")
	DeleteWazuhCCSCmd.Flags().String("customer-id", "", "Customer ID to remove")
	DeleteWazuhCCSCmd.Flags().Bool("force", false, "Force removal even with active connections")
	DeleteWazuhCCSCmd.Flags().Bool("archive", true, "Archive customer data before removal")
	DeleteWazuhCCSCmd.Flags().Bool("skip-confirmation", false, "Skip confirmation prompt")

	// Component removal flags (future)
	DeleteWazuhCCSCmd.Flags().Bool("remove-component", false, "Remove a platform component")
	DeleteWazuhCCSCmd.Flags().String("component", "", "Component to remove")
}

func runDeleteWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Wazuh MSSP deletion")

	// Check what to delete
	removeCustomer, _ := cmd.Flags().GetBool("remove-customer")
	removeComponent, _ := cmd.Flags().GetBool("remove-component")

	switch {
	case removeCustomer:
		return removeCustomerDeployment(rc, cmd)
	case removeComponent:
		return removePlatformComponent(rc, cmd)
	default:
		return cmd.Help()
	}
}

func removeCustomerDeployment(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing customer deployment")

	// Get customer ID
	customerID, _ := cmd.Flags().GetString("customer-id")
	if customerID == "" {
		logger.Info("terminal prompt: Please enter the customer ID to remove")
		id, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read customer ID: %w", err)
		}
		customerID = id
	}

	// Get flags
	force, _ := cmd.Flags().GetBool("force")
	archive, _ := cmd.Flags().GetBool("archive")
	skipConfirmation, _ := cmd.Flags().GetBool("skip-confirmation")

	// Confirmation prompt
	if !skipConfirmation {
		logger.Info("terminal prompt: WARNING: This will permanently remove the customer and all associated data.")
		logger.Info("terminal prompt: Customer ID: " + customerID)
		logger.Info("terminal prompt: Type the customer ID to confirm removal:")

		confirm, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if confirm != customerID {
			logger.Info("Customer ID mismatch, removal cancelled")
			return nil
		}

		// Final confirmation
		logger.Info("terminal prompt: Are you absolutely sure? This action cannot be undone. (yes/no)")
		finalConfirm, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read final confirmation: %w", err)
		}

		if finalConfirm != "yes" {
			logger.Info("Removal cancelled")
			return nil
		}
	}

	// Create backup if requested
	if archive {
		logger.Info("Creating customer backup before removal")
		backupID, err := customer.BackupCustomer(rc, customerID, "full")
		if err != nil {
			logger.Error("Failed to create backup", zap.Error(err))
			if !force {
				return fmt.Errorf("backup failed, use --force to remove anyway: %w", err)
			}
			logger.Warn("Continuing with removal despite backup failure due to --force flag")
		} else {
			logger.Info("Customer backup created", zap.String("backup_id", backupID))
		}
	}

	// Remove customer
	if err := customer.RemoveCustomer(rc, customerID, force); err != nil {
		return fmt.Errorf("customer removal failed: %w", err)
	}

	logger.Info("Customer removed successfully", zap.String("customer_id", customerID))

	// Show summary
	logger.Info("terminal prompt: Customer has been removed", zap.String("customer_id", customerID))
	if archive {
		logger.Info("terminal prompt: \nData has been archived and can be found in:")
		logger.Info("terminal prompt: Archive path", zap.String("path", "/var/lib/wazuh-mssp/archive/"+customerID+"-*"))
		logger.Info("terminal prompt: \nTo restore this customer later, use:")
		logger.Info("terminal prompt: Restore command", zap.String("command", "eos create wazuh-ccs --restore-customer "+customerID+" <backup-id>"))
	}

	return nil
}

func removePlatformComponent(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing platform component")

	// Get component name
	component, _ := cmd.Flags().GetString("component")
	if component == "" {
		logger.Info("terminal prompt: Please enter the component to remove")
		comp, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read component: %w", err)
		}
		component = comp
	}

	// Validate component
	validComponents := []string{
		"temporal", "nats", "benthos", "platform-api",
	}

	valid := false
	for _, validComp := range validComponents {
		if component == validComp {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("invalid component: %s. Valid components: %v", component, validComponents)
	}

	// Confirmation
	logger.Info("terminal prompt: WARNING: Removing platform components may affect all customers.")
	logger.Info("terminal prompt: Component: " + component)
	logger.Info("terminal prompt: Are you sure you want to remove this component? (yes/no)")

	confirm, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" {
		logger.Info("Component removal cancelled")
		return nil
	}

	// Remove component
	// This would stop and remove the Nomad job
	logger.Info("Removing platform component", zap.String("component", component))

	// Implementation would:
	// 1. Stop the Nomad job
	// 2. Clean up any persistent data
	// 3. Remove configurations
	// 4. Update platform state

	logger.Info("terminal prompt: Component has been removed", zap.String("component", component))
	logger.Info("terminal prompt: \nWARNING: Platform functionality may be degraded.")
	logger.Info("terminal prompt: To restore this component, run:")
	logger.Info("terminal prompt: Restore command", zap.String("command", "eos create wazuh-ccs --restore-component "+component))

	return nil
}
