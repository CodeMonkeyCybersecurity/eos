// cmd/delete/nomad.go

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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Remove HashiCorp Nomad and all associated data",
	Long: `Remove HashiCorp Nomad completely from the system using SaltStack.

This command will:
- Gracefully drain node if running as client
- Stop all running jobs (if server)
- Leave the Nomad cluster gracefully
- Stop and disable the Nomad service
- Remove the Nomad package and binary
- Delete configuration files (/etc/nomad.d) - unless --keep-config
- Remove data directories (/var/lib/nomad) - unless --keep-data
- Clean up log files (/var/log/nomad)
- Remove the nomad user and group - unless --keep-user
- Remove systemd service files

By default, this operation will create backups before removing data.

EXAMPLES:
  # Remove Nomad completely with confirmation prompt
  eos delete nomad

  # Remove Nomad without confirmation (use with caution)
  eos delete nomad --force

  # Remove Nomad but keep the data directory
  eos delete nomad --keep-data

  # Remove Nomad but preserve configuration
  eos delete nomad --keep-config

  # Remove Nomad but keep the user account
  eos delete nomad --keep-user

  # Remove with custom timeout for graceful shutdown
  eos delete nomad --timeout 60

  # Quick removal keeping config and data
  eos delete nomad --keep-config --keep-data --force`,
	RunE: eos.Wrap(runDeleteNomad),
}

var (
	nomadForceDelete bool
	nomadKeepData    bool
	nomadKeepConfig  bool
	nomadKeepUser    bool
	nomadTimeout     int
)

// NomadStatus represents the current state of Nomad installation
type NomadDeleteStatus struct {
	Installed       bool
	Running         bool
	Failed          bool
	ConfigValid     bool
	Version         string
	ServiceStatus   string
	ServerMode      bool
	ClientMode      bool
	NodeID          string
	ClusterMembers  []string
	RunningJobs     []string
	HasData         bool
	HasConfig       bool
	UserExists      bool
}

func checkNomadDeleteStatus(rc *eos_io.RuntimeContext) (*NomadDeleteStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &NomadDeleteStatus{}

	// Check if Nomad binary exists
	if nomadPath, err := exec.LookPath("nomad"); err == nil {
		status.Installed = true
		logger.Debug("Nomad binary found", zap.String("path", nomadPath))
		
		// Get version
		if output, err := exec.Command("nomad", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "nomad").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "nomad").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
		}
	}

	// Check server/client mode and cluster status if running
	if status.Running {
		// Check agent info
		if output, err := exec.Command("nomad", "agent-info").Output(); err == nil {
			outputStr := string(output)
			status.ServerMode = strings.Contains(outputStr, "server = true")
			status.ClientMode = strings.Contains(outputStr, "client = true")
			
			// Extract node ID
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "node_id") {
					parts := strings.Split(line, "=")
					if len(parts) > 1 {
						status.NodeID = strings.TrimSpace(parts[1])
					}
				}
			}
		}

		// Get server members (for server mode)
		if status.ServerMode {
			if output, err := exec.Command("nomad", "server", "members").Output(); err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "Name") {
						status.ClusterMembers = append(status.ClusterMembers, line)
					}
				}
			}
		}

		// Get running jobs
		if output, err := exec.Command("nomad", "job", "status", "-short").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "ID") {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						status.RunningJobs = append(status.RunningJobs, parts[0])
					}
				}
			}
		}
	}

	// Check for data directory
	if info, err := os.Stat("/var/lib/nomad"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/var/lib/nomad")
		status.HasData = len(entries) > 0
	}

	// Check for config directory
	if info, err := os.Stat("/etc/nomad.d"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/etc/nomad.d")
		status.HasConfig = len(entries) > 0
	}

	// Check if user exists
	if _, err := exec.Command("id", "nomad").Output(); err == nil {
		status.UserExists = true
	}

	// Validate config if present
	if status.Installed && status.HasConfig {
		if err := exec.Command("nomad", "config", "validate", "/etc/nomad.d/").Run(); err == nil {
			status.ConfigValid = true
		}
	}

	return status, nil
}

func runDeleteNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Create a context with extended timeout for delete operations
	deleteTimeout := time.Duration(nomadTimeout+300) * time.Second // Add 5 minutes to user timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, deleteTimeout)
	defer cancel()
	
	// Update the runtime context with extended timeout
	rc.Ctx = ctx

	logger.Info("Starting Nomad removal process",
		zap.Bool("force", nomadForceDelete),
		zap.Bool("keep_data", nomadKeepData),
		zap.Bool("keep_config", nomadKeepConfig),
		zap.Bool("keep_user", nomadKeepUser),
		zap.Int("timeout", nomadTimeout),
		zap.Duration("operation_timeout", deleteTimeout))

	// ASSESS - Check current Nomad status
	logger.Info("Checking current Nomad status")
	status, err := checkNomadDeleteStatus(rc)
	if err != nil {
		logger.Warn("Failed to check Nomad status", zap.Error(err))
		status = &NomadDeleteStatus{} // Use empty status
	}

	// Log detailed status
	logger.Info("Current Nomad installation status",
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.Bool("failed", status.Failed),
		zap.String("version", status.Version),
		zap.String("service_status", status.ServiceStatus),
		zap.Bool("has_data", status.HasData),
		zap.Bool("has_config", status.HasConfig),
		zap.Bool("user_exists", status.UserExists),
		zap.Bool("server_mode", status.ServerMode),
		zap.Bool("client_mode", status.ClientMode),
		zap.String("node_id", status.NodeID),
		zap.Int("cluster_members", len(status.ClusterMembers)),
		zap.Int("running_jobs", len(status.RunningJobs)))

	// Check if anything needs to be removed
	if !status.Installed && !status.HasData && !status.HasConfig && !status.UserExists {
		logger.Info("Nomad is not installed on this system - nothing to remove")
		return nil
	}

	// Show warnings for running jobs/cluster
	if len(status.RunningJobs) > 0 {
		logger.Warn("Nomad has running jobs",
			zap.Int("job_count", len(status.RunningJobs)))
		for _, job := range status.RunningJobs {
			logger.Info("Running job", zap.String("job", job))
		}
	}

	if len(status.ClusterMembers) > 1 {
		logger.Warn("Nomad is part of a cluster",
			zap.Int("member_count", len(status.ClusterMembers)))
		for _, member := range status.ClusterMembers {
			logger.Info("Cluster member", zap.String("member", member))
		}
	}

	// Confirmation prompt
	if !nomadForceDelete {
		prompt := "Are you sure you want to remove Nomad"
		details := []string{}
		
		if status.HasData && !nomadKeepData {
			details = append(details, "all data will be deleted")
		}
		if status.HasConfig && !nomadKeepConfig {
			details = append(details, "all configurations will be removed")
		}
		if status.UserExists && !nomadKeepUser {
			details = append(details, "the nomad user will be removed")
		}
		if len(status.RunningJobs) > 0 {
			details = append(details, fmt.Sprintf("%d running jobs will be stopped", len(status.RunningJobs)))
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
			logger.Info("Nomad deletion cancelled by user")
			return nil
		}
	}

	// INTERVENE - Apply removal using REST API or fallback to direct execution
	logger.Info("Applying Nomad removal")
	
	// Try REST API first
	apiURL := "https://localhost:8000"
	restInstaller := getNomadRESTInstaller(apiURL, true) // Skip TLS verify for self-signed cert
	
	// Check authentication
	logger.Info("Attempting to authenticate with Salt REST API")
	if err := restInstaller.Authenticate(rc.Ctx, "salt", "saltpass"); err != nil {
		logger.Warn("Failed to authenticate with Salt REST API, falling back to direct execution", zap.Error(err))
		
		// Fallback to direct salt-call execution
		return runDeleteNomadDirectSalt(rc, ctx, status, nomadForceDelete, nomadKeepData, 
			nomadKeepConfig, nomadKeepUser, nomadTimeout)
	}
	
	logger.Info("Successfully authenticated with Salt REST API")
	
	// Prepare removal configuration
	removeConfig := &nomad.NomadRemoveConfig{
		Force:      nomadForceDelete,
		KeepData:   nomadKeepData,
		KeepConfig: nomadKeepConfig,
		KeepUser:   nomadKeepUser,
		Timeout:    nomadTimeout,
		ServerMode: status.ServerMode,
		ClientMode: status.ClientMode,
		NodeID:     status.NodeID,
	}
	
	// Execute removal via REST API
	logger.Info("Removing Nomad via Salt REST API")
	if err := restInstaller.RemoveNomad(rc, removeConfig); err != nil {
		logger.Error("Nomad removal via REST API failed", zap.Error(err))
		return fmt.Errorf("nomad removal failed: %w", err)
	}
	
	logger.Info("Nomad removal via REST API completed successfully")

	// EVALUATE - Verify removal
	logger.Info("Verifying Nomad removal")
	
	// Re-check status after removal
	finalStatus, err := checkNomadDeleteStatus(rc)
	if err != nil {
		logger.Warn("Failed to verify final status", zap.Error(err))
	} else {
		remainingComponents := []string{}
		
		if finalStatus.Installed {
			remainingComponents = append(remainingComponents, "binary")
		}
		if finalStatus.UserExists && !nomadKeepUser {
			remainingComponents = append(remainingComponents, "user")
		}
		if finalStatus.HasConfig && !nomadKeepConfig {
			remainingComponents = append(remainingComponents, "config")
		}
		if finalStatus.HasData && !nomadKeepData {
			remainingComponents = append(remainingComponents, "data")
		}
		
		if len(remainingComponents) == 0 {
			logger.Info("Nomad removal completed successfully - all components removed")
		} else {
			logger.Warn("Some Nomad components remain",
				zap.Strings("remaining", remainingComponents))
			
			// This is only an error if we didn't intend to keep them
			if (finalStatus.HasData && !nomadKeepData) || 
			   (finalStatus.HasConfig && !nomadKeepConfig) || 
			   (finalStatus.UserExists && !nomadKeepUser) {
				return fmt.Errorf("failed to remove all components: %v", remainingComponents)
			}
		}
	}
	
	// Show summary
	logger.Info("Nomad removal summary",
		zap.Bool("data_kept", nomadKeepData && finalStatus.HasData),
		zap.Bool("config_kept", nomadKeepConfig && finalStatus.HasConfig),
		zap.Bool("user_kept", nomadKeepUser && finalStatus.UserExists))
	
	if nomadKeepData || nomadKeepConfig {
		logger.Info("terminal prompt: Preserved components can be manually removed later if needed")
	}
	
	logger.Info("terminal prompt: You can now safely reinstall Nomad with 'eos create nomad'")
	
	return nil
}

// getNomadRESTInstaller creates a REST installer instance
func getNomadRESTInstaller(apiURL string, skipTLSVerify bool) *nomad.RESTInstaller {
	return nomad.NewRESTInstaller(apiURL, skipTLSVerify)
}

// runDeleteNomadDirectSalt is a fallback function that uses direct salt-call execution
func runDeleteNomadDirectSalt(rc *eos_io.RuntimeContext, ctx context.Context, status *NomadDeleteStatus,
	force, keepData, keepConfig, keepUser bool, timeout int) error {
	
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Using direct salt-call execution for Nomad removal")
	
	// Check if SaltStack is available
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		logger.Error("SaltStack is required for Nomad removal")
		return eos_err.NewUserError("saltstack is required for nomad removal - salt-call not found in PATH")
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
	stateFile := "/opt/eos/salt/states/hashicorp/nomad_remove.sls"
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
		"nomad": map[string]interface{}{
			"ensure":      "absent",
			"force":       force,
			"keep_data":   keepData,
			"keep_config": keepConfig,
			"keep_user":   keepUser,
			"timeout":     timeout,
			"server_mode": status.ServerMode,
			"client_mode": status.ClientMode,
			"node_id":     status.NodeID,
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
		"hashicorp.nomad_remove",
		"--output=json",
		"--output-indent=2",
		"pillar=" + string(pillarJSON),
	}

	logger.Info("Executing Salt state for removal",
		zap.String("state", "hashicorp.nomad_remove"),
		zap.Strings("args", saltArgs))

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
	
	return nil
}

func init() {
	DeleteNomadCmd.Flags().BoolVarP(&nomadForceDelete, "force", "f", false, "Force deletion without confirmation prompt")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepData, "keep-data", false, "Preserve Nomad data directory (/var/lib/nomad)")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepConfig, "keep-config", false, "Preserve Nomad configuration (/etc/nomad.d)")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepUser, "keep-user", false, "Preserve nomad system user account")
	DeleteNomadCmd.Flags().IntVar(&nomadTimeout, "timeout", 30, "Timeout in seconds for graceful node drain")
	
	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteNomadCmd)
}