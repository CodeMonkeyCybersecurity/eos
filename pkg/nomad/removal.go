package nomad

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UninstallConfig holds configuration for Nomad removal
type UninstallConfig struct {
	Force          bool
	RemoveData     bool
	RemoveConfig   bool
	RemoveUser     bool
	PreserveLogs   bool
	PreserveBackup bool
	Timeout        int
}

// UninstallState represents the comprehensive state of Nomad installation
type UninstallState struct {
	// Installation status
	BinaryInstalled  bool
	PackageInstalled bool
	Version          string

	// Service status
	ServiceRunning bool
	ServiceEnabled bool
	ServiceFailed  bool
	ServiceStatus  string

	// Operational status
	ServerMode     bool
	ClientMode     bool
	NodeID         string
	ClusterMembers []string
	RunningJobs    []string

	// File system status
	ConfigExists bool
	DataExists   bool
	UserExists   bool
	ExistingPaths []string
	ConfigValid   bool
}

// NomadUninstaller handles Nomad removal following Assess→Intervene→Evaluate pattern
type NomadUninstaller struct {
	rc     *eos_io.RuntimeContext
	config *UninstallConfig
	logger otelzap.LoggerWithCtx
	state  *UninstallState
}

// NewNomadUninstaller creates a new Nomad uninstaller
func NewNomadUninstaller(rc *eos_io.RuntimeContext, config *UninstallConfig) *NomadUninstaller {
	return &NomadUninstaller{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
		state:  &UninstallState{},
	}
}

// Assess checks the current state of Nomad installation
func (nu *NomadUninstaller) Assess() (*UninstallState, error) {
	nu.logger.Info("Assessing Nomad installation state")

	// Check if Nomad binary exists
	if nomadPath, err := exec.LookPath("nomad"); err == nil {
		nu.state.BinaryInstalled = true
		nu.logger.Debug("Nomad binary found", zap.String("path", nomadPath))

		// Get version
		if output, err := exec.Command("nomad", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				nu.state.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "nomad").Output(); err == nil {
		nu.state.ServiceStatus = strings.TrimSpace(string(output))
		nu.state.ServiceRunning = (nu.state.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "nomad").Run() == nil {
			nu.state.ServiceFailed = true
			nu.state.ServiceStatus = "failed"
		}
	}

	// Check if service is enabled
	if exec.Command("systemctl", "is-enabled", "nomad").Run() == nil {
		nu.state.ServiceEnabled = true
	}

	// Check server/client mode and cluster status if running
	if nu.state.ServiceRunning || nu.state.BinaryInstalled {
		// Check agent info
		if output, err := exec.Command("nomad", "agent-info").Output(); err == nil {
			outputStr := string(output)
			nu.state.ServerMode = strings.Contains(outputStr, "server = true")
			nu.state.ClientMode = strings.Contains(outputStr, "client = true")

			// Extract node ID
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "node_id") {
					parts := strings.Split(line, "=")
					if len(parts) > 1 {
						nu.state.NodeID = strings.TrimSpace(parts[1])
					}
				}
			}
		}

		// Get server members (for server mode)
		if nu.state.ServerMode {
			if output, err := exec.Command("nomad", "server", "members").Output(); err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "Name") {
						nu.state.ClusterMembers = append(nu.state.ClusterMembers, line)
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
						nu.state.RunningJobs = append(nu.state.RunningJobs, parts[0])
					}
				}
			}
		}
	}

	// Check for data directory
	if info, err := os.Stat("/var/lib/nomad"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/var/lib/nomad")
		nu.state.DataExists = len(entries) > 0
		nu.state.ExistingPaths = append(nu.state.ExistingPaths, "/var/lib/nomad")
	}

	// Check for config directory
	if info, err := os.Stat("/etc/nomad.d"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/etc/nomad.d")
		nu.state.ConfigExists = len(entries) > 0
		nu.state.ExistingPaths = append(nu.state.ExistingPaths, "/etc/nomad.d")
	}

	// Check other common paths
	commonPaths := []string{"/opt/nomad", "/var/log/nomad"}
	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			nu.state.ExistingPaths = append(nu.state.ExistingPaths, path)
		}
	}

	// Check if user exists
	if _, err := exec.Command("id", "nomad").Output(); err == nil {
		nu.state.UserExists = true
	}

	// Validate config if present
	if nu.state.BinaryInstalled && nu.state.ConfigExists {
		if err := exec.Command("nomad", "config", "validate", "/etc/nomad.d/").Run(); err == nil {
			nu.state.ConfigValid = true
		}
	}

	nu.logger.Info("Nomad assessment complete",
		zap.Bool("binary_installed", nu.state.BinaryInstalled),
		zap.Bool("service_running", nu.state.ServiceRunning),
		zap.Bool("has_data", nu.state.DataExists),
		zap.Bool("has_config", nu.state.ConfigExists),
		zap.Int("running_jobs", len(nu.state.RunningJobs)))

	return nu.state, nil
}

// Uninstall performs the complete Nomad uninstallation following Assess→Intervene→Evaluate
func (nu *NomadUninstaller) Uninstall() error {
	nu.logger.Info("Starting Nomad uninstallation")

	// ASSESS
	if _, err := nu.Assess(); err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// INTERVENE - Stop jobs and services
	if err := nu.StopJobs(); err != nil {
		nu.logger.Warn("Failed to stop jobs cleanly", zap.Error(err))
	}

	if err := nu.Stop(); err != nil {
		nu.logger.Warn("Failed to stop service cleanly", zap.Error(err))
	}

	// Remove package or binary
	if err := nu.RemovePackage(); err != nil {
		nu.logger.Warn("Failed to remove package", zap.Error(err))
	}

	// Clean up files
	if err := nu.CleanFiles(); err != nil {
		return fmt.Errorf("failed to clean files: %w", err)
	}

	// Remove user if requested
	if nu.config.RemoveUser && nu.state.UserExists {
		if err := nu.RemoveUser(); err != nil {
			nu.logger.Warn("Failed to remove user", zap.Error(err))
		}
	}

	// Clean environment variables
	if err := nu.CleanEnvironmentVariables(); err != nil {
		nu.logger.Warn("Failed to clean environment variables", zap.Error(err))
	}

	// EVALUATE
	if err := nu.Verify(); err != nil {
		nu.logger.Warn("Verification found issues", zap.Error(err))
	}

	nu.logger.Info("Nomad uninstallation completed")
	return nil
}

// StopJobs stops all running Nomad jobs
func (nu *NomadUninstaller) StopJobs() error {
	if !nu.state.ServiceRunning || len(nu.state.RunningJobs) == 0 {
		nu.logger.Debug("No running jobs to stop")
		return nil
	}

	nu.logger.Info("Stopping Nomad jobs", zap.Int("count", len(nu.state.RunningJobs)))

	for _, job := range nu.state.RunningJobs {
		nu.logger.Info("Stopping job", zap.String("job", job))
		ctx, cancel := context.WithTimeout(nu.rc.Ctx, 30*time.Second)
		_, err := execute.Run(ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "stop", "-purge", job},
			Capture: true,
		})
		cancel()
		if err != nil {
			nu.logger.Warn("Failed to stop job", zap.String("job", job), zap.Error(err))
		}
	}

	// Wait for jobs to terminate
	nu.logger.Info("Waiting for jobs to terminate")
	time.Sleep(5 * time.Second)

	return nil
}

// Stop stops and disables the Nomad service
func (nu *NomadUninstaller) Stop() error {
	nu.logger.Info("Stopping Nomad service")

	// Stop service
	if nu.state.ServiceRunning {
		if _, err := execute.Run(nu.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "nomad"},
			Timeout: 30 * time.Second,
		}); err != nil {
			nu.logger.Warn("Failed to stop service", zap.Error(err))
		}
	}

	// Disable service
	if nu.state.ServiceEnabled {
		if _, err := execute.Run(nu.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", "nomad"},
			Timeout: 10 * time.Second,
		}); err != nil {
			nu.logger.Warn("Failed to disable service", zap.Error(err))
		}
	}

	// Reset failed state
	_, _ = execute.Run(nu.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"reset-failed", "nomad.service"},
		Timeout: 5 * time.Second,
	})

	// Kill any remaining processes
	_, _ = execute.Run(nu.rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-TERM", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})
	time.Sleep(2 * time.Second)
	_, _ = execute.Run(nu.rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-KILL", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})

	// Remove systemd service files
	serviceFiles := []string{
		"/etc/systemd/system/nomad.service",
		"/lib/systemd/system/nomad.service",
		"/usr/lib/systemd/system/nomad.service",
	}

	for _, file := range serviceFiles {
		if _, err := os.Stat(file); err == nil {
			nu.logger.Debug("Removing systemd service file", zap.String("file", file))
			if err := os.Remove(file); err != nil {
				nu.logger.Warn("Failed to remove service file", zap.String("file", file), zap.Error(err))
			}
		}
	}

	// Reload systemd
	_, _ = execute.Run(nu.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 10 * time.Second,
	})

	return nil
}

// RemovePackage removes Nomad package or binary
func (nu *NomadUninstaller) RemovePackage() error {
	nu.logger.Info("Removing Nomad package")

	// Try package removal first
	if output, err := execute.Run(nu.rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", "nomad"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && strings.Contains(output, "nomad") {
		nu.logger.Info("Removing Nomad via apt")
		_, _ = execute.Run(nu.rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"remove", "-y", "nomad"},
			Timeout: 60 * time.Second,
		})
		_, _ = execute.Run(nu.rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"purge", "-y", "nomad"},
			Timeout: 60 * time.Second,
		})
	}

	// Remove binary directly
	binaryPaths := []string{"/usr/local/bin/nomad", "/usr/bin/nomad"}
	for _, path := range binaryPaths {
		if _, err := os.Stat(path); err == nil {
			nu.logger.Debug("Removing binary", zap.String("path", path))
			if err := os.Remove(path); err != nil {
				nu.logger.Warn("Failed to remove binary", zap.String("path", path), zap.Error(err))
			}
		}
	}

	return nil
}

// CleanFiles removes Nomad configuration and data files
func (nu *NomadUninstaller) CleanFiles() error {
	nu.logger.Info("Cleaning Nomad files")

	// Directories to remove based on config
	dirsToRemove := []string{}

	if nu.config.RemoveData {
		dirsToRemove = append(dirsToRemove, "/var/lib/nomad", "/opt/nomad")
	}

	if nu.config.RemoveConfig {
		dirsToRemove = append(dirsToRemove, "/etc/nomad.d")
	}

	if !nu.config.PreserveLogs {
		dirsToRemove = append(dirsToRemove, "/var/log/nomad")
	}

	// Always remove these
	dirsToRemove = append(dirsToRemove, "/opt/nomad/bin")

	for _, dir := range dirsToRemove {
		if _, err := os.Stat(dir); err == nil {
			nu.logger.Debug("Removing directory", zap.String("dir", dir))
			if err := os.RemoveAll(dir); err != nil {
				nu.logger.Warn("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	}

	return nil
}

// RemoveUser removes the nomad system user and group
func (nu *NomadUninstaller) RemoveUser() error {
	nu.logger.Info("Removing nomad user")

	// Remove user
	if _, err := execute.Run(nu.rc.Ctx, execute.Options{
		Command: "userdel",
		Args:    []string{"-r", "nomad"},
		Timeout: 10 * time.Second,
	}); err != nil {
		nu.logger.Debug("Failed to remove user", zap.Error(err))
	}

	// Remove group if it still exists
	if _, err := execute.Run(nu.rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{"nomad"},
		Timeout: 10 * time.Second,
	}); err != nil {
		nu.logger.Debug("Failed to remove group", zap.Error(err))
	}

	return nil
}

// CleanEnvironmentVariables removes Nomad environment variables
func (nu *NomadUninstaller) CleanEnvironmentVariables() error {
	nu.logger.Info("Cleaning Nomad environment variables")

	nomadVars := []string{
		"NOMAD_ADDR",
		"NOMAD_TOKEN",
		"NOMAD_REGION",
		"NOMAD_NAMESPACE",
		"NOMAD_CACERT",
		"NOMAD_CLIENT_CERT",
		"NOMAD_CLIENT_KEY",
	}

	// Clean from /etc/environment
	if content, err := os.ReadFile("/etc/environment"); err == nil {
		lines := strings.Split(string(content), "\n")
		var filtered []string
		for _, line := range lines {
			keep := true
			for _, v := range nomadVars {
				if strings.HasPrefix(line, v+"=") {
					keep = false
					break
				}
			}
			if keep {
				filtered = append(filtered, line)
			}
		}
		if len(filtered) != len(lines) {
			_ = os.WriteFile("/etc/environment", []byte(strings.Join(filtered, "\n")), shared.ConfigFilePerm)
		}
	}

	// Clean from /etc/profile.d/nomad.sh
	profileScript := "/etc/profile.d/nomad.sh"
	if _, err := os.Stat(profileScript); err == nil {
		nu.logger.Debug("Removing profile script", zap.String("file", profileScript))
		_ = os.Remove(profileScript)
	}

	return nil
}

// Verify checks if Nomad was properly removed
func (nu *NomadUninstaller) Verify() error {
	nu.logger.Info("Verifying Nomad removal")

	issues := []string{}

	// Check if binary still exists
	if _, err := exec.LookPath("nomad"); err == nil {
		issues = append(issues, "Nomad binary still in PATH")
	}

	// Check if service still exists
	_, _ = execute.Run(nu.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 5 * time.Second,
	})

	if output, err := execute.Run(nu.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", "nomad.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && strings.Contains(output, "nomad.service") && !strings.Contains(output, "0 unit files") {
		issues = append(issues, "Nomad service still exists")
	}

	// Check if processes still running
	if output, err := execute.Run(nu.rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil && output != "" {
		issues = append(issues, "Nomad processes still running")
	}

	// Check if user still exists (only if we were supposed to remove it)
	if nu.config.RemoveUser {
		if _, err := exec.Command("id", "nomad").Output(); err == nil {
			issues = append(issues, "Nomad user still exists")
		}
	}

	if len(issues) > 0 {
		nu.logger.Warn("Nomad removal verification found issues", zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found", len(issues))
	}

	nu.logger.Info("Nomad removal verification passed")
	return nil
}

// RemoveNomadCompletely removes Nomad using comprehensive direct removal
// This provides complete removal when orchestration is not available
func RemoveNomadCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Nomad removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Nomad state
	nomadState := assessNomadState(rc)
	logger.Info("Nomad assessment completed",
		zap.Bool("binary_exists", nomadState.BinaryExists),
		zap.Bool("service_exists", nomadState.ServiceExists),
		zap.Bool("api_accessible", nomadState.APIAccessible),
		zap.Int("running_jobs", len(nomadState.RunningJobs)))

	// INTERVENE - Remove Nomad components
	if err := removeNomadComponents(rc, nomadState, keepData); err != nil {
		return fmt.Errorf("failed to remove Nomad components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyNomadRemoval(rc); err != nil {
		logger.Warn("Nomad removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Nomad removal completed successfully")
	return nil
}

// NomadState represents the current state of Nomad installation
type NomadState struct {
	BinaryExists  bool
	ServiceExists bool
	APIAccessible bool
	RunningJobs   []string
	DataDirs      []string
	ConfigFiles   []string
}

// assessNomadState checks the current state of Nomad installation
func assessNomadState(rc *eos_io.RuntimeContext) *NomadState {
	state := &NomadState{}

	// Check if Nomad binary exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		state.BinaryExists = true
	}

	// Check if service exists (don't log errors - expected during cleanup)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", "nomad.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.ServiceExists = true
	}

	// Check API accessibility
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()
	if output, err := execute.Run(ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"status"},
		Capture: true,
	}); err == nil && output != "" {
		state.APIAccessible = true

		// Try to get running jobs
		if jobOutput, err := execute.Run(ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "list", "-short"},
			Capture: true,
		}); err == nil {
			state.RunningJobs = parseNomadJobs(jobOutput)
		}
	}

	// Check for data directories
	dataDirs := []string{
		"/opt/nomad",
		"/opt/nomad/data",
		"/etc/nomad.d",
		"/var/lib/nomad",
		"/var/log/nomad",
	}
	for _, dir := range dataDirs {
		if _, err := os.Stat(dir); err == nil {
			state.DataDirs = append(state.DataDirs, dir)
		}
	}

	// Check for config files
	configFiles := []string{
		"/etc/nomad.d/nomad.hcl",
		"/etc/systemd/system/nomad.service",
		"/usr/local/bin/nomad",
		"/usr/bin/nomad",
	}
	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			state.ConfigFiles = append(state.ConfigFiles, file)
		}
	}

	return state
}

// removeNomadComponents removes all Nomad components based on current state
func removeNomadComponents(rc *eos_io.RuntimeContext, state *NomadState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop running jobs if API is accessible
	if state.APIAccessible && len(state.RunningJobs) > 0 {
		logger.Info("Stopping Nomad jobs", zap.Int("count", len(state.RunningJobs)))
		for _, job := range state.RunningJobs {
			logger.Info("Stopping Nomad job", zap.String("job", job))
			// Use context with timeout for each job
			ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
			_, err := execute.Run(ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", job},
				Capture: true,
			})
			cancel()
			if err != nil {
				logger.Debug("Failed to stop job (may already be stopped)",
					zap.String("job", job), zap.Error(err))
			}
		}

		// Wait for jobs to terminate
		logger.Info("Waiting for jobs to terminate...")
		time.Sleep(5 * time.Second)
	}

	// Stop and disable Nomad service
	if state.ServiceExists {
		logger.Info("Stopping Nomad service")
		// Stop service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "nomad"},
			Timeout: 30 * time.Second,
		})
		// Disable service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", "nomad"},
			Timeout: 10 * time.Second,
		})
	}

	// Kill any remaining Nomad processes
	// TODO: Add graceful shutdown attempt before force kill
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-TERM", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})
	time.Sleep(2 * time.Second)
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-KILL", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})

	// Remove binaries and config files
	logger.Info("Removing Nomad binaries and configs")
	systemdReloadNeeded := false
	for _, file := range state.ConfigFiles {
		if err := os.Remove(file); err != nil {
			// Use RemoveAll for directories that might contain files
			if err := os.RemoveAll(file); err != nil {
				logger.Debug("Failed to remove file", zap.String("file", file), zap.Error(err))
			}
		} else {
			// Check if we removed a systemd unit file
			if strings.HasSuffix(file, ".service") && strings.Contains(file, "/systemd/system/") {
				systemdReloadNeeded = true
			}
		}
	}

	// Ensure the systemd service file is really gone
	systemdFile := "/etc/systemd/system/nomad.service"
	if _, err := os.Stat(systemdFile); err == nil {
		logger.Info("Removing systemd service file", zap.String("file", systemdFile))
		if err := os.Remove(systemdFile); err != nil {
			logger.Warn("Failed to remove systemd service file", zap.String("file", systemdFile), zap.Error(err))
		}
		systemdReloadNeeded = true
	}

	// Reload systemd if we removed unit files
	if systemdReloadNeeded {
		logger.Info("Reloading systemd daemon after unit file removal")
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"daemon-reload"},
			Timeout: 10 * time.Second,
		}); err != nil {
			logger.Warn("Failed to reload systemd daemon", zap.Error(err))
		}
	}

	// Remove directories
	if !keepData {
		logger.Info("Removing Nomad directories")
		for _, dir := range state.DataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	} else {
		logger.Info("Keeping Nomad data directories as requested")
		// Still remove non-data directories
		nonDataDirs := []string{"/etc/nomad.d", "/opt/nomad/bin"}
		for _, dir := range nonDataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	}

	// Remove HashiCorp repository if no other HashiCorp tools remain
	// FIXME: This should check if other HashiCorp tools are installed before removing repo
	removeHashiCorpRepo(rc)

	// Reload systemd
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 10 * time.Second,
	})

	return nil
}

// verifyNomadRemoval checks if Nomad was properly removed
func verifyNomadRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Nomad removal")

	issues := []string{}

	// Check if binary still exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		issues = append(issues, "Nomad binary still found in PATH")
	}

	// Check if service still exists - but first reload systemd to ensure cache is fresh
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 5 * time.Second,
	})

	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", "nomad.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		// Only report as issue if the service is actually listed (not just header)
		if strings.Contains(output, "nomad.service") && !strings.Contains(output, "0 unit files listed") {
			issues = append(issues, "Nomad service unit file still exists")
		}
	}

	// Check if processes still running (don't log error if none found)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil && output != "" {
		issues = append(issues, "Nomad processes still running")
	}

	// Check directories
	remainingDirs := []string{}
	for _, dir := range []string{"/opt/nomad", "/etc/nomad.d"} {
		if _, err := os.Stat(dir); err == nil {
			remainingDirs = append(remainingDirs, dir)
		}
	}
	if len(remainingDirs) > 0 {
		issues = append(issues, fmt.Sprintf("Directories still exist: %v", remainingDirs))
	}

	if len(issues) > 0 {
		logger.Warn("Nomad removal verification found issues",
			zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found", len(issues))
	}

	logger.Info("Nomad removal verification passed")
	return nil
}

// parseNomadJobs extracts job names from nomad job list output
func parseNomadJobs(output string) []string {
	// TODO: Implement proper parsing of Nomad job list output
	// For now, return empty slice
	return []string{}
}

// removeHashiCorpRepo removes HashiCorp APT repository if safe
func removeHashiCorpRepo(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if other HashiCorp tools are installed
	hashicorpTools := []string{"vault", "consul", "terraform", "packer", "boundary"}
	otherToolsExist := false

	for _, tool := range hashicorpTools {
		if tool == "nomad" {
			continue // Skip nomad since we're removing it
		}
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{tool},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			otherToolsExist = true
			logger.Debug("Other HashiCorp tool found, keeping repository",
				zap.String("tool", tool))
			break
		}
	}

	if !otherToolsExist {
		logger.Info("Removing HashiCorp APT repository")
		// Remove repository files
		repoFiles := []string{
			"/etc/apt/sources.list.d/hashicorp.list",
			"/usr/share/keyrings/hashicorp-archive-keyring.gpg",
		}
		for _, file := range repoFiles {
			if err := os.Remove(file); err != nil {
				logger.Debug("Failed to remove repo file",
					zap.String("file", file), zap.Error(err))
			}
		}
	}
}
