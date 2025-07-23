// cmd/delete/consul.go

package delete

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Remove HashiCorp Consul and all associated data",
	Long: `Remove HashiCorp Consul completely from the system using SaltStack.

This command will:
- Stop and disable the Consul service
- Remove the Consul package
- Delete all configuration files (/etc/consul.d)
- Remove all data directories (/var/lib/consul)
- Clean up log files (/var/log/consul)
- Remove the consul user and group
- Remove systemd service files
- Clean up any Vault integration if present

WARNING: This operation is destructive and will remove ALL Consul data.
Make sure to backup any important data before proceeding.

EXAMPLES:
  # Remove Consul with confirmation prompt
  eos delete consul

  # Remove Consul without confirmation (use with caution)
  eos delete consul --force`,
	RunE: eos.Wrap(runDeleteConsul),
}

var (
	forceDelete bool
)

func runDeleteConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// ASSESS - Check if Consul is installed
	logger.Info("Checking if Consul is installed")
	
	consulInstalled := false
	if _, err := exec.LookPath("consul"); err == nil {
		consulInstalled = true
	}
	
	// Check if service exists
	serviceExists := false
	if err := exec.Command("systemctl", "list-unit-files", "consul.service").Run(); err == nil {
		serviceExists = true
	}
	
	if !consulInstalled && !serviceExists {
		logger.Info("Consul is not installed on this system")
		return nil
	}

	// Confirmation prompt
	if !forceDelete {
		logger.Info("terminal prompt: Are you sure you want to remove Consul and all its data? This action cannot be undone. [y/N]")
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}
		
		if response != "y" && response != "Y" {
			logger.Info("Consul deletion cancelled by user")
			return nil
		}
	}

	logger.Info("Starting Consul removal process",
		zap.Bool("force", forceDelete))

	// INTERVENE - Apply SaltStack state for removal
	logger.Info("Applying SaltStack state for Consul removal")
	
	// Check if SaltStack is available
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		logger.Error("SaltStack is required for Consul removal")
		return fmt.Errorf("saltstack is required for consul removal - salt-call not found in PATH")
	}
	logger.Info("SaltStack detected", zap.String("salt_call", saltCallPath))
	
	// Prepare Salt pillar data for removal
	pillarData := map[string]interface{}{
		"consul": map[string]interface{}{
			"ensure": "absent",
		},
	}

	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	// Execute Salt state for removal
	saltArgs := []string{
		"--local",
		"--file-root=/opt/eos/salt/states",
		"--pillar-root=/opt/eos/salt/pillar",
		"state.apply",
		"hashicorp.consul_remove",
		"--output=json",
		"--output-indent=2",
		"pillar=" + string(pillarJSON),
	}

	logger.Info("Executing Salt state for removal",
		zap.String("state", "hashicorp.consul_remove"),
		zap.Strings("args", saltArgs))

	output, err := exec.Command("salt-call", saltArgs...).CombinedOutput()
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("salt state execution failed: %w", err)
	}

	logger.Info("Salt state executed",
		zap.String("output", string(output)))

	// EVALUATE - Verify removal
	logger.Info("Verifying Consul removal")
	
	// Check if consul binary still exists
	if _, err := exec.LookPath("consul"); err == nil {
		logger.Warn("Consul binary still exists after removal attempt")
	}
	
	// Check if service still exists
	if err := exec.Command("systemctl", "status", "consul").Run(); err == nil {
		logger.Warn("Consul service still exists after removal attempt")
	}
	
	// Check if directories still exist
	directories := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
	}
	
	for _, dir := range directories {
		if _, err := os.Stat(dir); err == nil {
			logger.Warn("Directory still exists after removal",
				zap.String("directory", dir))
		}
	}

	logger.Info("Consul removal completed successfully")
	
	return nil
}

func init() {
	DeleteConsulCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force deletion without confirmation prompt")
	
	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteConsulCmd)
}