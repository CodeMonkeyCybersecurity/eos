// cmd/delete/consul.go

package delete

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
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
- Gracefully leave the Consul cluster (if possible)
- Stop and disable the Consul service
- Remove the Consul package and binary
- Delete configuration files (/etc/consul.d) - unless --keep-config
- Remove data directories (/var/lib/consul) - unless --keep-data
- Clean up log files (/var/log/consul)
- Remove the consul user and group - unless --keep-user
- Remove systemd service files
- Clean up any Vault integration if present

By default, this operation will create backups before removing data.

EXAMPLES:
  # Remove Consul completely with confirmation prompt
  eos delete consul

  # Remove Consul without confirmation (use with caution)
  eos delete consul --force

  # Remove Consul but keep the data directory
  eos delete consul --keep-data

  # Remove Consul but preserve configuration
  eos delete consul --keep-config

  # Remove Consul but keep the user account
  eos delete consul --keep-user

  # Remove with custom timeout for graceful shutdown
  eos delete consul --timeout 60

  # Quick removal keeping config and data
  eos delete consul --keep-config --keep-data --force`,
	RunE: eos.Wrap(runDeleteConsul),
}

var (
	forceDelete bool
	keepData    bool
	keepConfig  bool
	keepUser    bool
	timeout     int
)

// ConsulStatus represents the current state of Consul installation
type ConsulStatus struct {
	Installed       bool
	Running         bool
	Failed          bool
	ConfigValid     bool
	Version         string
	ServiceStatus   string
	ClusterMembers  []string
	HasData         bool
	HasConfig       bool
	UserExists      bool
}

func checkConsulStatus(rc *eos_io.RuntimeContext) (*ConsulStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &ConsulStatus{}

	// Check if Consul binary exists
	if consulPath, err := exec.LookPath("consul"); err == nil {
		status.Installed = true
		logger.Debug("Consul binary found", zap.String("path", consulPath))
		
		// Get version
		if output, err := exec.Command("consul", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "consul").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "consul").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
		}
	}

	// Check for cluster members if running
	if status.Running {
		if output, err := exec.Command("consul", "members").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Node") {
					status.ClusterMembers = append(status.ClusterMembers, line)
				}
			}
		}
	}

	// Check for data directory
	if info, err := os.Stat("/var/lib/consul"); err == nil && info.IsDir() {
		// Check if directory has content
		entries, _ := os.ReadDir("/var/lib/consul")
		status.HasData = len(entries) > 0
	}

	// Check for config directory
	if info, err := os.Stat("/etc/consul.d"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/etc/consul.d")
		status.HasConfig = len(entries) > 0
	}

	// Check if user exists
	if _, err := exec.Command("id", "consul").Output(); err == nil {
		status.UserExists = true
	}

	// Validate config if present
	if status.Installed && status.HasConfig {
		if err := exec.Command("consul", "validate", "/etc/consul.d/").Run(); err == nil {
			status.ConfigValid = true
		}
	}

	return status, nil
}

func runDeleteConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Create a context with extended timeout for delete operations
	// Delete operations may take longer due to graceful shutdown, backups, etc.
	deleteTimeout := time.Duration(timeout+300) * time.Second // Add 5 minutes to user timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, deleteTimeout)
	defer cancel()
	
	// Update the runtime context with extended timeout
	rc.Ctx = ctx

	logger.Info("Starting Consul removal process",
		zap.Bool("force", forceDelete),
		zap.Bool("keep_data", keepData),
		zap.Bool("keep_config", keepConfig),
		zap.Bool("keep_user", keepUser),
		zap.Int("timeout", timeout),
		zap.Duration("operation_timeout", deleteTimeout))

	// ASSESS - Check current Consul status
	logger.Info("Checking current Consul status")
	status, err := checkConsulStatus(rc)
	if err != nil {
		logger.Warn("Failed to check Consul status", zap.Error(err))
		status = &ConsulStatus{} // Use empty status
	}

	// Log detailed status
	logger.Info("Current Consul installation status",
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.Bool("failed", status.Failed),
		zap.String("version", status.Version),
		zap.String("service_status", status.ServiceStatus),
		zap.Bool("has_data", status.HasData),
		zap.Bool("has_config", status.HasConfig),
		zap.Bool("user_exists", status.UserExists),
		zap.Int("cluster_members", len(status.ClusterMembers)))

	// Check if anything needs to be removed
	if !status.Installed && !status.HasData && !status.HasConfig && !status.UserExists {
		logger.Info("Consul is not installed on this system - nothing to remove")
		return nil
	}

	// Show cluster warning if there are other members
	if len(status.ClusterMembers) > 1 {
		logger.Warn("Consul is part of a cluster",
			zap.Int("member_count", len(status.ClusterMembers)))
		for _, member := range status.ClusterMembers {
			logger.Info("Cluster member", zap.String("member", member))
		}
	}

	// Confirmation prompt
	if !forceDelete {
		prompt := "Are you sure you want to remove Consul"
		details := []string{}
		
		if status.HasData && !keepData {
			details = append(details, "all data will be deleted")
		}
		if status.HasConfig && !keepConfig {
			details = append(details, "all configurations will be removed")
		}
		if status.UserExists && !keepUser {
			details = append(details, "the consul user will be removed")
		}
		
		if len(details) > 0 {
			prompt += " (" + strings.Join(details, ", ") + ")"
		}
		prompt += "? This action cannot be undone. [y/N]"
		
		logger.Info("terminal prompt: " + prompt)
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}
		
		if response != "y" && response != "Y" {
			logger.Info("Consul deletion cancelled by user")
			return nil
		}
	}

	// INTERVENE - Apply SaltStack state for removal
	logger.Info("Applying SaltStack state for Consul removal")
	
	// Check if SaltStack is available
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		logger.Error("SaltStack is required for Consul removal")
		return eos_err.NewUserError("saltstack is required for consul removal - salt-call not found in PATH")
	}
	logger.Info("SaltStack detected", zap.String("salt_call", saltCallPath))
	
	// Test Salt functionality
	logger.Info("Testing Salt functionality")
	testCmd := exec.Command("salt-call", "--local", "test.ping")
	if testOutput, err := testCmd.CombinedOutput(); err != nil {
		logger.Error("Salt test failed",
			zap.Error(err),
			zap.String("output", string(testOutput)))
		return fmt.Errorf("salt appears to be broken: %w", err)
	} else {
		logger.Debug("Salt test successful", zap.String("output", string(testOutput)))
	}
	
	// Check if the salt state file exists
	stateFile := "/opt/eos/salt/states/hashicorp/consul_remove.sls"
	if info, err := os.Stat(stateFile); err != nil {
		logger.Error("Salt state file not found",
			zap.String("path", stateFile),
			zap.Error(err))
		return fmt.Errorf("salt state file not found: %s", stateFile)
	} else {
		logger.Info("Salt state file found",
			zap.String("path", stateFile),
			zap.Int64("size", info.Size()))
	}
	
	// Prepare Salt pillar data for removal
	pillarData := map[string]interface{}{
		"consul": map[string]interface{}{
			"ensure":      "absent",
			"force":       forceDelete,
			"keep_data":   keepData,
			"keep_config": keepConfig,
			"keep_user":   keepUser,
			"timeout":     timeout,
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
		zap.Strings("args", saltArgs),
		zap.String("pillar_json", string(pillarJSON)))

	// Create command with context for better control
	saltCmd := exec.CommandContext(ctx, "salt-call", saltArgs...)
	
	// Set up output capture
	var outputBuilder strings.Builder
	var outputMu sync.Mutex
	
	// Set up pipes to capture output in real-time
	stdout, err := saltCmd.StdoutPipe()
	if err != nil {
		logger.Error("Failed to create stdout pipe", zap.Error(err))
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderr, err := saltCmd.StderrPipe()
	if err != nil {
		logger.Error("Failed to create stderr pipe", zap.Error(err))
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	logger.Info("Starting Salt command execution")
	
	// Start the command
	if err := saltCmd.Start(); err != nil {
		logger.Error("Failed to start Salt command",
			zap.Error(err),
			zap.String("command", "salt-call"),
			zap.Strings("args", saltArgs))
		return fmt.Errorf("failed to start salt command: %w", err)
	}
	
	logger.Info("Salt command started, waiting for completion",
		zap.Int("pid", saltCmd.Process.Pid))
	
	// Read output in real-time
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				outputMu.Lock()
				outputBuilder.Write(buf[:n])
				outputMu.Unlock()
				logger.Debug("Salt stdout", zap.String("output", string(buf[:n])))
			}
			if err != nil {
				break
			}
		}
	}()
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				outputMu.Lock()
				outputBuilder.Write(buf[:n])
				outputMu.Unlock()
				logger.Warn("Salt stderr", zap.String("output", string(buf[:n])))
			}
			if err != nil {
				break
			}
		}
	}()
	
	// Wait for command to complete
	logger.Info("Waiting for Salt command to complete")
	err = saltCmd.Wait()
	wg.Wait() // Wait for output readers to finish
	
	outputMu.Lock()
	output := outputBuilder.String()
	outputMu.Unlock()
	
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", output))
		
		// Check process state for more details
		if saltCmd.ProcessState != nil {
			logger.Error("Salt process details",
				zap.Int("exit_code", saltCmd.ProcessState.ExitCode()),
				zap.Bool("success", saltCmd.ProcessState.Success()),
				zap.String("string", saltCmd.ProcessState.String()))
		}
		
		// Check if context was cancelled
		if ctx.Err() != nil {
			logger.Error("Operation cancelled or timed out",
				zap.Error(ctx.Err()))
			return fmt.Errorf("operation cancelled or timed out: %w", ctx.Err())
		}
		
		return fmt.Errorf("salt state execution failed: %w", err)
	}
	
	logger.Info("Salt state executed successfully")
	logger.Debug("Salt output", zap.String("output", output))

	// EVALUATE - Verify removal
	logger.Info("Verifying Consul removal")
	
	// Re-check status after removal
	finalStatus, err := checkConsulStatus(rc)
	if err != nil {
		logger.Warn("Failed to verify final status", zap.Error(err))
	} else {
		remainingComponents := []string{}
		
		if finalStatus.Installed {
			remainingComponents = append(remainingComponents, "binary")
		}
		if finalStatus.UserExists && !keepUser {
			remainingComponents = append(remainingComponents, "user")
		}
		if finalStatus.HasConfig && !keepConfig {
			remainingComponents = append(remainingComponents, "config")
		}
		if finalStatus.HasData && !keepData {
			remainingComponents = append(remainingComponents, "data")
		}
		
		if len(remainingComponents) == 0 {
			logger.Info("Consul removal completed successfully - all components removed")
		} else {
			logger.Warn("Some Consul components remain",
				zap.Strings("remaining", remainingComponents))
			
			// This is only an error if we didn't intend to keep them
			if (finalStatus.HasData && !keepData) || 
			   (finalStatus.HasConfig && !keepConfig) || 
			   (finalStatus.UserExists && !keepUser) {
				return fmt.Errorf("failed to remove all components: %v", remainingComponents)
			}
		}
	}
	
	// Show summary
	logger.Info("Consul removal summary",
		zap.Bool("data_kept", keepData && finalStatus.HasData),
		zap.Bool("config_kept", keepConfig && finalStatus.HasConfig),
		zap.Bool("user_kept", keepUser && finalStatus.UserExists))
	
	if keepData || keepConfig {
		logger.Info("terminal prompt: Preserved components can be manually removed later if needed")
	}
	
	logger.Info("terminal prompt: You can now safely reinstall Consul with 'eos create consul'")
	
	return nil
}

func init() {
	DeleteConsulCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force deletion without confirmation prompt")
	DeleteConsulCmd.Flags().BoolVar(&keepData, "keep-data", false, "Preserve Consul data directory (/var/lib/consul)")
	DeleteConsulCmd.Flags().BoolVar(&keepConfig, "keep-config", false, "Preserve Consul configuration (/etc/consul.d)")
	DeleteConsulCmd.Flags().BoolVar(&keepUser, "keep-user", false, "Preserve consul system user account")
	DeleteConsulCmd.Flags().IntVar(&timeout, "timeout", 30, "Timeout in seconds for graceful cluster leave")
	
	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteConsulCmd)
}