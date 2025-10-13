// pkg/vault/uninstall.go

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UninstallConfig contains configuration for Vault uninstallation
type UninstallConfig struct {
	Force          bool   // Skip confirmation prompts
	RemoveData     bool   // Remove data directories
	RemoveUser     bool   // Remove vault user/group
	Distro         string // Distribution type (debian, rhel)
	PreserveLogs   bool   // Keep log files
	PreserveBackup bool   // Keep backup files
}

// UninstallState represents the current state of Vault installation
type UninstallState struct {
	BinaryInstalled  bool
	ServiceRunning   bool
	ServiceEnabled   bool
	ConfigExists     bool
	DataExists       bool
	UserExists       bool
	Version          string
	ExistingPaths    []string
	PackageInstalled bool
}

// DeletionStep represents a single step in the deletion process
type DeletionStep struct {
	Name      string
	Completed bool
	Success   bool
	Error     error
	Timestamp time.Time
}

// DeletionTransaction tracks the deletion process for recovery
type DeletionTransaction struct {
	StartTime   time.Time
	Steps       []DeletionStep
	LogPath     string
	Interrupted bool
}

// VaultUninstaller handles safe removal of Vault
type VaultUninstaller struct {
	rc          *eos_io.RuntimeContext
	config      *UninstallConfig
	logger      otelzap.LoggerWithCtx
	state       *UninstallState
	transaction *DeletionTransaction
	sigChan     chan os.Signal
}

// NewVaultUninstaller creates a new Vault uninstaller
func NewVaultUninstaller(rc *eos_io.RuntimeContext, config *UninstallConfig) *VaultUninstaller {
	if config == nil {
		config = &UninstallConfig{
			Force:      false,
			RemoveData: true,
			RemoveUser: true,
		}
	}

	// Auto-detect distribution if not specified
	if config.Distro == "" {
		config.Distro = detectDistro()
	}

	// Initialize transaction tracking with secure log directory
	logDir := "/var/log/eos"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// If we can't create log directory, fall back to temp
		logDir = os.TempDir()
	}

	logPath := fmt.Sprintf("%s/vault-deletion-%s.log", logDir, time.Now().Format("20060102-150405"))
	transaction := &DeletionTransaction{
		StartTime: time.Now(),
		Steps:     []DeletionStep{},
		LogPath:   logPath,
	}

	return &VaultUninstaller{
		rc:          rc,
		config:      config,
		logger:      otelzap.Ctx(rc.Ctx),
		transaction: transaction,
		sigChan:     make(chan os.Signal, 1),
	}
}

// Assess checks the current state of Vault installation
func (vu *VaultUninstaller) Assess() (*UninstallState, error) {
	vu.logger.Info("Assessing Vault installation state")

	state := &UninstallState{
		ExistingPaths: []string{},
	}

	// Check if binary is installed
	if binaryPath, err := exec.LookPath("vault"); err == nil {
		state.BinaryInstalled = true
		vu.logger.Info("Vault binary found", zap.String("path", binaryPath))

		// Get version
		if output, err := exec.Command("vault", "version").Output(); err == nil {
			state.Version = strings.TrimSpace(string(output))
			vu.logger.Info("Current Vault version", zap.String("version", state.Version))
		}
	}

	// Check if service is running
	if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
		status := strings.TrimSpace(string(output))
		state.ServiceRunning = (status == "active")
		if state.ServiceRunning {
			vu.logger.Info("Vault service is currently active")
		}
	}

	// Check if service is enabled
	if err := exec.Command("systemctl", "is-enabled", "vault").Run(); err == nil {
		state.ServiceEnabled = true
	}

	// Check for configuration and data directories
	checkPaths := map[string]*bool{
		"/etc/vault.d":   &state.ConfigExists,
		"/opt/vault":     &state.DataExists,
		"/var/lib/vault": nil, // Just track existence
		"/var/log/vault": nil,
	}

	for path, stateFlag := range checkPaths {
		if _, err := os.Stat(path); err == nil {
			state.ExistingPaths = append(state.ExistingPaths, path)
			if stateFlag != nil {
				*stateFlag = true
			}
		}
	}

	// Check if vault user exists
	if err := exec.Command("id", "vault").Run(); err == nil {
		state.UserExists = true
		vu.logger.Info("Vault user exists")
	}

	// Check if installed via package manager
	var checkCmd *exec.Cmd
	switch vu.config.Distro {
	case "debian":
		checkCmd = exec.Command("dpkg", "-l", "vault")
	case "rhel":
		checkCmd = exec.Command("rpm", "-q", "vault")
	}
	if checkCmd != nil && checkCmd.Run() == nil {
		state.PackageInstalled = true
	}

	vu.state = state
	vu.logger.Info("Assessment complete",
		zap.Bool("binary_installed", state.BinaryInstalled),
		zap.Bool("service_running", state.ServiceRunning),
		zap.Bool("config_exists", state.ConfigExists),
		zap.Bool("data_exists", state.DataExists),
		zap.Int("existing_paths", len(state.ExistingPaths)))

	return state, nil
}

// Stop stops all Vault services and removes systemd service files
// Uses a robust multi-stage approach: graceful stop → force kill → process kill
func (vu *VaultUninstaller) Stop() error {
	vu.logger.Info("Stopping Vault services")

	// Stage 1: Try graceful stop with timeout
	vu.logger.Debug("Stage 1: Attempting graceful stop of vault service (30s timeout)")
	if err := vu.stopServiceWithTimeout("vault", 30*time.Second); err != nil {
		vu.logger.Warn("Graceful stop failed or timed out", zap.Error(err))

		// Stage 2: Force kill the service
		vu.logger.Debug("Stage 2: Force killing vault service with systemctl kill")
		killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer killCancel()
		killCmd := exec.CommandContext(killCtx, "systemctl", "kill", "--signal=SIGKILL", "vault")
		if killErr := killCmd.Run(); killErr != nil {
			vu.logger.Warn("systemctl kill failed, will try direct process kill", zap.Error(killErr))
		}
		time.Sleep(2 * time.Second) // Give it time to die
	}

	// Stage 3: Stop vault-agent if present (with timeout)
	vu.logger.Debug("Stopping vault-agent (if present)")
	if err := vu.stopServiceWithTimeout("vault-agent", 15*time.Second); err != nil {
		vu.logger.Debug("vault-agent not running or doesn't exist")
		// Force kill vault-agent too
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		_ = exec.CommandContext(killCtx, "systemctl", "kill", "--signal=SIGKILL", "vault-agent").Run()
	}

	// Stage 4: Direct process termination - SIGTERM first
	vu.logger.Debug("Stage 4: Sending SIGTERM to any remaining vault processes")
	pkillCtx, pkillCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pkillCancel()
	if err := exec.CommandContext(pkillCtx, "pkill", "-TERM", "vault").Run(); err == nil {
		vu.logger.Debug("Sent SIGTERM to vault processes, waiting 3s for graceful shutdown")
		time.Sleep(3 * time.Second)
	}

	// Stage 5: Check if processes still exist, use SIGKILL if needed
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer checkCancel()
	if err := exec.CommandContext(checkCtx, "pgrep", "vault").Run(); err == nil {
		vu.logger.Warn("Vault processes still running after SIGTERM, sending SIGKILL")
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		if err := exec.CommandContext(killCtx, "pkill", "-9", "vault").Run(); err != nil {
			vu.logger.Error("Failed to kill vault processes with SIGKILL", zap.Error(err))
			return fmt.Errorf("vault processes could not be killed: %w", err)
		}
		time.Sleep(1 * time.Second)
	}

	// Stage 6: Final verification - no vault processes should remain
	finalCheck, finalCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer finalCancel()
	if err := exec.CommandContext(finalCheck, "pgrep", "vault").Run(); err == nil {
		vu.logger.Error("CRITICAL: Vault processes still running after all kill attempts")
		// List them for debugging
		psCtx, psCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer psCancel()
		if output, psErr := exec.CommandContext(psCtx, "ps", "aux").CombinedOutput(); psErr == nil {
			vu.logger.Error("Current vault processes", zap.String("ps_output", string(output)))
		}
		return fmt.Errorf("vault processes could not be terminated after all attempts")
	}

	vu.logger.Info("All vault processes successfully stopped")

	// Disable services
	if vu.state != nil && vu.state.ServiceEnabled {
		vu.logger.Debug("Disabling vault services")
		_ = exec.Command("systemctl", "disable", "vault").Run()
		_ = exec.Command("systemctl", "disable", "vault-agent").Run()
	}

	// Remove systemd service files
	vu.logger.Info("Removing systemd service files")
	serviceFiles := []string{
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent.service",
		"/lib/systemd/system/vault.service",
		"/usr/lib/systemd/system/vault.service",
	}

	for _, serviceFile := range serviceFiles {
		if err := os.Remove(serviceFile); err != nil {
			if !os.IsNotExist(err) {
				vu.logger.Debug("Failed to remove service file",
					zap.String("file", serviceFile),
					zap.Error(err))
			}
		} else {
			vu.logger.Debug("Removed service file", zap.String("file", serviceFile))
		}
	}

	// Reset failed state to clean up systemd completely
	exec.Command("systemctl", "reset-failed", "vault.service").Run()
	exec.Command("systemctl", "reset-failed", "vault-agent.service").Run()

	vu.logger.Info("Vault services stopped and cleaned")
	return nil
}

// stopServiceWithTimeout stops a systemd service with a specified timeout
func (vu *VaultUninstaller) stopServiceWithTimeout(serviceName string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "stop", serviceName)
	startTime := time.Now()

	vu.logger.Debug("Stopping service",
		zap.String("service", serviceName),
		zap.Duration("timeout", timeout))

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			vu.logger.Warn("Service stop timed out",
				zap.String("service", serviceName),
				zap.Duration("waited", time.Since(startTime)))
			return fmt.Errorf("timeout after %v", timeout)
		}
		return err
	}

	vu.logger.Debug("Service stopped successfully",
		zap.String("service", serviceName),
		zap.Duration("duration", time.Since(startTime)))
	return nil
}

// RemovePackage removes Vault package via package manager
func (vu *VaultUninstaller) RemovePackage() error {
	if vu.state != nil && !vu.state.PackageInstalled {
		vu.logger.Debug("Vault not installed via package manager, skipping package removal")
		return nil
	}

	vu.logger.Info("Removing Vault package",
		zap.String("distro", vu.config.Distro))

	var cmd *exec.Cmd
	switch vu.config.Distro {
	case "debian":
		cmd = exec.Command("apt-get", "remove", "--purge", "-y", "vault")
	case "rhel":
		cmd = exec.Command("dnf", "remove", "-y", "vault")
	default:
		vu.logger.Warn("Unknown distribution, skipping package removal",
			zap.String("distro", vu.config.Distro))
		return nil
	}

	if err := cmd.Run(); err != nil {
		vu.logger.Warn("Failed to remove package", zap.Error(err))
		return fmt.Errorf("package removal failed: %w", err)
	}

	// Autoremove on Debian-based systems
	if vu.config.Distro == "debian" {
		exec.Command("apt-get", "autoremove", "-y").Run()
	}

	return nil
}

// CleanFiles removes all Vault files and directories
func (vu *VaultUninstaller) CleanFiles() ([]string, map[string]error) {
	vu.logger.Info("Purging all Vault files and configurations")

	removed, errs := Purge(vu.rc, vu.config.Distro)

	if len(removed) > 0 {
		vu.logger.Info("Removed Vault files",
			zap.Int("count", len(removed)),
			zap.Strings("files", removed))
	}

	if len(errs) > 0 {
		vu.logger.Warn("Some files could not be removed",
			zap.Int("error_count", len(errs)))
		for path, err := range errs {
			vu.logger.Debug("Failed to remove path",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	return removed, errs
}

// RemoveUser removes the vault system user and group
func (vu *VaultUninstaller) RemoveUser() error {
	if !vu.config.RemoveUser {
		vu.logger.Debug("Skipping user removal (disabled in config)")
		return nil
	}

	if vu.state != nil && !vu.state.UserExists {
		vu.logger.Debug("Vault user does not exist, skipping removal")
		return nil
	}

	vu.logger.Info("Removing vault user and group")

	// Remove user (will also remove home directory with -r)
	if err := exec.Command("userdel", "-r", "vault").Run(); err != nil {
		vu.logger.Warn("Failed to remove vault user", zap.Error(err))
	}

	// Remove group
	if err := exec.Command("groupdel", "vault").Run(); err != nil {
		vu.logger.Debug("Failed to remove vault group (may not exist or still in use)")
	}

	return nil
}

// CleanEnvironmentVariables removes Vault-related environment variables
func (vu *VaultUninstaller) CleanEnvironmentVariables() error {
	vu.logger.Info("Cleaning Vault environment variables")

	// Files to clean
	envFiles := []string{
		"/etc/environment",
		"/etc/profile.d/vault.sh",
	}

	// Environment variables to remove
	vaultVars := []string{
		"VAULT_ADDR",
		"VAULT_CACERT",
		"VAULT_CLIENT_CERT",
		"VAULT_CLIENT_KEY",
		"VAULT_SKIP_VERIFY",
		"VAULT_TOKEN",
	}

	for _, envFile := range envFiles {
		// Check if file exists
		if _, err := os.Stat(envFile); os.IsNotExist(err) {
			continue
		}

		// For /etc/profile.d/vault.sh, just remove the whole file
		if envFile == "/etc/profile.d/vault.sh" {
			if err := os.Remove(envFile); err != nil {
				if !os.IsNotExist(err) {
					vu.logger.Debug("Failed to remove vault profile",
						zap.String("file", envFile),
						zap.Error(err))
				}
			} else {
				vu.logger.Debug("Removed vault profile", zap.String("file", envFile))
			}
			continue
		}

		// For /etc/environment, use sed to remove lines
		for _, varName := range vaultVars {
			cmd := exec.Command("sed", "-i", fmt.Sprintf("/%s/d", varName), envFile)
			if err := cmd.Run(); err != nil {
				vu.logger.Debug("Failed to remove env var from file",
					zap.String("var", varName),
					zap.String("file", envFile),
					zap.Error(err))
			}
		}
	}

	vu.logger.Info("Environment variables cleaned")
	return nil
}

// ReloadSystemd reloads systemd daemon configuration
func (vu *VaultUninstaller) ReloadSystemd() error {
	vu.logger.Debug("Reloading systemd daemon")
	return exec.Command("systemctl", "daemon-reload").Run()
}

// Verify checks if Vault was completely removed
func (vu *VaultUninstaller) Verify() ([]string, error) {
	vu.logger.Info("Verifying Vault removal")

	stillPresent := []string{}

	// Check if binary still in PATH
	if _, err := exec.LookPath("vault"); err == nil {
		stillPresent = append(stillPresent, "vault binary still in PATH")
	}

	// Check directories
	checkDirs := map[string]string{
		"/etc/vault.d":                            "config directory",
		"/opt/vault":                              "data directory",
		"/var/lib/vault":                          "data directory",
		"/var/log/vault":                          "log directory",
		"/etc/systemd/system/vault.service":       "systemd service",
		"/etc/systemd/system/vault-agent.service": "vault-agent service",
	}

	for dir, desc := range checkDirs {
		if _, err := os.Stat(dir); err == nil {
			stillPresent = append(stillPresent, fmt.Sprintf("%s (%s)", desc, dir))
		}
	}

	if len(stillPresent) > 0 {
		vu.logger.Warn("Some Vault components still present",
			zap.Strings("remaining", stillPresent))
		return stillPresent, nil
	}

	vu.logger.Info(" Vault removal completed successfully - all components removed")
	return stillPresent, nil
}

// logStep records a deletion step to the transaction log
func (vu *VaultUninstaller) logStep(stepName string, success bool, err error) {
	step := DeletionStep{
		Name:      stepName,
		Completed: true,
		Success:   success,
		Error:     err,
		Timestamp: time.Now(),
	}
	vu.transaction.Steps = append(vu.transaction.Steps, step)

	// Write to log file
	logEntry := fmt.Sprintf("%s - %s: %s",
		step.Timestamp.Format(time.RFC3339),
		map[bool]string{true: "SUCCESS", false: "FAILED"}[success],
		stepName)
	if err != nil {
		logEntry += fmt.Sprintf(" - %v", err)
	}
	logEntry += "\n"

	// Append to transaction log file with secure permissions (root-only readable)
	f, fileErr := os.OpenFile(vu.transaction.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if fileErr != nil {
		vu.logger.Debug("Failed to write transaction log", zap.Error(fileErr))
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(logEntry)
}

// setupSignalHandling sets up graceful shutdown on interrupt
func (vu *VaultUninstaller) setupSignalHandling(ctx context.Context, cancel context.CancelFunc) {
	signal.Notify(vu.sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		defer signal.Stop(vu.sigChan) // Clean up signal notifications
		defer close(vu.sigChan)       // Close channel on exit

		select {
		case sig := <-vu.sigChan:
			vu.logger.Error("  DELETION INTERRUPTED",
				zap.String("signal", sig.String()),
				zap.String("status", "partial_deletion"),
				zap.String("transaction_log", vu.transaction.LogPath))

			vu.transaction.Interrupted = true
			vu.logStep(fmt.Sprintf("INTERRUPTED by signal %s", sig.String()), false, fmt.Errorf("user interrupt"))

			// Log remaining components for recovery
			vu.logger.Error("System may be in inconsistent state",
				zap.String("recovery", "Run 'sudo eos rm vault --force' to retry deletion"),
				zap.String("transaction_log", vu.transaction.LogPath))

			cancel()
			os.Exit(130) // Standard exit code for Ctrl+C
		case <-ctx.Done():
			// Context cancelled normally, clean exit
			return
		}
	}()
}

// displayPreDeletionSummary shows what will be deleted
func (vu *VaultUninstaller) displayPreDeletionSummary() {
	vu.logger.Info("terminal prompt: \n╔════════════════════════════════════════════════════════════════╗")
	vu.logger.Info("terminal prompt: ║  PRE-DELETION SUMMARY - Components to be REMOVED              ║")
	vu.logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	vu.logger.Info("terminal prompt: ")

	if vu.state.BinaryInstalled {
		vu.logger.Info("terminal prompt:  Binary:")
		vu.logger.Info(fmt.Sprintf("terminal prompt:    - /usr/local/bin/vault (%s)", vu.state.Version))
		vu.logger.Info("terminal prompt:    - /usr/bin/vault (if present)")
	}

	if vu.state.ServiceRunning || vu.state.ServiceEnabled {
		vu.logger.Info("terminal prompt: ")
		vu.logger.Info("terminal prompt:  Service:")
		vu.logger.Info("terminal prompt:    - /etc/systemd/system/vault.service")
		if vu.state.ServiceRunning {
			vu.logger.Info("terminal prompt:    - Currently RUNNING (will be stopped)")
		}
	}

	if len(vu.state.ExistingPaths) > 0 {
		vu.logger.Info("terminal prompt: ")
		vu.logger.Info("terminal prompt:  Files & Directories:")
		for _, path := range vu.state.ExistingPaths {
			vu.logger.Info(fmt.Sprintf("terminal prompt:    - %s", path))
		}
	}

	if vu.state.UserExists {
		vu.logger.Info("terminal prompt: ")
		vu.logger.Info("terminal prompt:  System Resources:")
		vu.logger.Info("terminal prompt:    - User: vault")
		vu.logger.Info("terminal prompt:    - Group: vault")
	}

	vu.logger.Info("terminal prompt: ")
	vu.logger.Info("terminal prompt:  Environment Variables:")
	vu.logger.Info("terminal prompt:    - VAULT_ADDR, VAULT_CACERT, and related variables")
	vu.logger.Info("terminal prompt: ")
}

// displayPostDeletionSummary shows what was deleted and verification
func (vu *VaultUninstaller) displayPostDeletionSummary(removed []string, errs map[string]error, stillPresent []string) {
	vu.logger.Info("terminal prompt: \n╔════════════════════════════════════════════════════════════════╗")
	vu.logger.Info("terminal prompt: ║  DELETION COMPLETE - Verification Report                      ║")
	vu.logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	vu.logger.Info("terminal prompt: ")

	// Success metrics
	vu.logger.Info(fmt.Sprintf("terminal prompt:  Files Removed: %d", len(removed)))
	if len(errs) > 0 {
		vu.logger.Info(fmt.Sprintf("terminal prompt:   Errors: %d", len(errs)))
	}

	// Component verification
	vu.logger.Info("terminal prompt: ")
	vu.logger.Info("terminal prompt: 🔍 Component Verification:")

	checks := []struct {
		name    string
		present bool
	}{
		{"Binary removed", len(stillPresent) == 0 || !strings.Contains(strings.Join(stillPresent, " "), "binary")},
		{"Service removed", len(stillPresent) == 0 || !strings.Contains(strings.Join(stillPresent, " "), "service")},
		{"Config removed", len(stillPresent) == 0 || !strings.Contains(strings.Join(stillPresent, " "), "config")},
		{"Data removed", len(stillPresent) == 0 || !strings.Contains(strings.Join(stillPresent, " "), "data")},
	}

	for _, check := range checks {
		status := "✓"
		if !check.present {
			status = "✗"
		}
		vu.logger.Info(fmt.Sprintf("terminal prompt:    [%s] %s", status, check.name))
	}

	if len(stillPresent) > 0 {
		vu.logger.Warn("terminal prompt: ")
		vu.logger.Warn("terminal prompt:   Remaining Components:")
		for _, component := range stillPresent {
			vu.logger.Warn(fmt.Sprintf("terminal prompt:    - %s", component))
		}
		vu.logger.Warn("terminal prompt: ")
		vu.logger.Warn("terminal prompt: Run 'sudo eos rm vault --force' to retry removal")
	}

	vu.logger.Info("terminal prompt: ")
	vu.logger.Info(fmt.Sprintf("terminal prompt: 📄 Transaction Log: %s", vu.transaction.LogPath))
	vu.logger.Info(fmt.Sprintf("terminal prompt: ⏱  Duration: %v", time.Since(vu.transaction.StartTime).Round(time.Second)))
	vu.logger.Info("terminal prompt: ")
}

// Uninstall performs the complete uninstallation process
// Follows Assess → Intervene → Evaluate pattern with signal handling and transaction logging
func (vu *VaultUninstaller) Uninstall() error {
	// Setup context with cancellation for signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling FIRST - before any operations
	vu.setupSignalHandling(ctx, cancel)
	vu.logStep("STARTED: Vault deletion process", true, nil)

	// ASSESS - Use existing state (already assessed in command handler)
	// This removes the duplicate assessment
	if vu.state == nil {
		// State should already be set, but if not, assess now
		state, err := vu.Assess()
		if err != nil {
			return fmt.Errorf("assessment failed: %w", err)
		}
		vu.state = state
	}

	// If nothing is installed, return early
	if !vu.state.BinaryInstalled && !vu.state.ServiceRunning && len(vu.state.ExistingPaths) == 0 {
		vu.logger.Info("Vault is not installed and no data directories found")
		vu.logStep("COMPLETE: Nothing to remove", true, nil)
		return nil
	}

	// Display pre-deletion summary
	vu.displayPreDeletionSummary()

	// INTERVENE - Remove Vault with progress tracking
	vu.logger.Info("  Beginning Vault uninstallation")
	totalSteps := 7
	currentStep := 0

	// Step 1: Stop services
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Stopping Vault services...", currentStep, totalSteps))
	if err := vu.Stop(); err != nil {
		vu.logger.Warn("Error stopping services", zap.Error(err))
		vu.logStep("Stop services", false, err)
		// Continue anyway
	} else {
		vu.logStep("Stop services", true, nil)
	}

	// Step 2: Remove package
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Removing Vault package...", currentStep, totalSteps))
	if err := vu.RemovePackage(); err != nil {
		vu.logger.Warn("Error removing package", zap.Error(err))
		vu.logStep("Remove package", false, err)
		// Continue anyway
	} else {
		vu.logStep("Remove package", true, nil)
	}

	// Step 3: Clean files and directories
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Cleaning files and directories...", currentStep, totalSteps))
	removed, errs := vu.CleanFiles()
	if len(errs) > 0 {
		// Log each error individually for transparency
		for path, err := range errs {
			vu.logger.Warn("Failed to remove path during cleanup",
				zap.String("path", path),
				zap.Error(err))
		}
		vu.logStep(fmt.Sprintf("Clean files (removed %d, %d errors)", len(removed), len(errs)), false, fmt.Errorf("%d errors occurred", len(errs)))
	} else {
		vu.logStep(fmt.Sprintf("Clean files (removed %d)", len(removed)), true, nil)
	}

	// Step 4: Remove user and group
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Removing vault user and group...", currentStep, totalSteps))
	if err := vu.RemoveUser(); err != nil {
		vu.logger.Warn("Error removing user", zap.Error(err))
		vu.logStep("Remove user/group", false, err)
	} else {
		vu.logStep("Remove user/group", true, nil)
	}

	// Step 5: Clean environment variables
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Cleaning environment variables...", currentStep, totalSteps))
	if err := vu.CleanEnvironmentVariables(); err != nil {
		vu.logger.Warn("Error cleaning environment variables", zap.Error(err))
		vu.logStep("Clean environment", false, err)
	} else {
		vu.logStep("Clean environment", true, nil)
	}

	// Step 6: Reload systemd
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Reloading systemd daemon...", currentStep, totalSteps))
	if err := vu.ReloadSystemd(); err != nil {
		vu.logger.Debug("Error reloading systemd", zap.Error(err))
		vu.logStep("Reload systemd", false, err)
	} else {
		vu.logStep("Reload systemd", true, nil)
	}

	// Step 7: EVALUATE - Verify removal
	currentStep++
	vu.logger.Info(fmt.Sprintf("[%d/%d] Verifying removal...", currentStep, totalSteps))
	stillPresent, err := vu.Verify()
	if len(stillPresent) > 0 {
		vu.logStep(fmt.Sprintf("Verification: %d components remain", len(stillPresent)), false, nil)
	} else {
		vu.logStep("Verification: Complete removal confirmed", true, nil)
	}

	// Log completion
	vu.logStep("FINISHED: Vault deletion process", len(stillPresent) == 0, nil)

	// Display post-deletion summary
	vu.displayPostDeletionSummary(removed, errs, stillPresent)

	// Final status logging
	vu.logger.Info("Vault uninstallation process finished",
		zap.Int("files_removed", len(removed)),
		zap.Int("errors", len(errs)),
		zap.Int("remaining_components", len(stillPresent)),
		zap.Duration("duration", time.Since(vu.transaction.StartTime)))

	return err
}

// detectDistro attempts to detect the Linux distribution
func detectDistro() string {
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rhel"
	}
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	return "unknown"
}
