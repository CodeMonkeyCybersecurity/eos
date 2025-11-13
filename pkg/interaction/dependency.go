// pkg/interaction/dependency.go
//
// Human-centric dependency checking with informed consent
// Follows Eos P0 philosophy: Technology serves humans, not the other way around

package interaction

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DependencyConfig defines a dependency to check and potentially install
type DependencyConfig struct {
	Name           string                      // Friendly name (e.g., "Ollama", "Docker")
	Description    string                      // What it's for (e.g., "local LLM embeddings")
	CheckCommand   string                      // Command to check if installed (e.g., "docker")
	CheckArgs      []string                    // Args for check command (e.g., ["info"])
	InstallCmd     string                      // Installation command (shown to user)
	StartCmd       string                      // Optional: command to start service
	Required       bool                        // If true, operation cannot continue without it
	AutoInstall    bool                        // If true, attempt automatic installation (must be safe)
	AutoStart      bool                        // If true, attempt automatic start (must be safe)
	CustomCheckFn  func(context.Context) error // Optional custom check function
	InstallTimeout time.Duration               // Optional: timeout for installation (default: 10 minutes)
	StartTimeout   time.Duration               // Optional: timeout for service start (default: 2 minutes)
	CheckTimeout   time.Duration               // Optional: timeout for check commands (default: 30 seconds)
}

// DependencyCheckResult contains the result of a dependency check
type DependencyCheckResult struct {
	Name        string
	Found       bool
	Running     bool
	Version     string
	UserDecline bool // User declined to install
}

// Default timeouts for dependency operations
const (
	DefaultInstallTimeout = 10 * time.Minute // Large downloads (e.g., Ollama binary)
	DefaultStartTimeout   = 2 * time.Minute  // Service startup (e.g., systemd)
	DefaultCheckTimeout   = 30 * time.Second // Quick health checks
)

// CheckDependencyWithPrompt checks if a dependency exists and prompts user to install if missing
// This is the human-centric pattern: NEVER silently fail, ALWAYS offer informed consent
//
// Pattern follows: ASSESS → INFORM → CONSENT → INTERVENE → EVALUATE
func CheckDependencyWithPrompt(rc *eos_io.RuntimeContext, config DependencyConfig) (*DependencyCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &DependencyCheckResult{
		Name: config.Name,
	}

	// === ASSESS: Check if dependency exists ===
	logger.Debug("Checking dependency", zap.String("dependency", config.Name))

	// Set default timeouts if not provided
	checkTimeout := config.CheckTimeout
	if checkTimeout == 0 {
		checkTimeout = DefaultCheckTimeout
	}

	var checkErr error
	if config.CustomCheckFn != nil {
		// Use custom check function if provided
		checkErr = config.CustomCheckFn(rc.Ctx)
	} else {
		// Use standard command check with timeout
		checkErr = checkDependencyCommand(rc.Ctx, config.CheckCommand, config.CheckArgs, checkTimeout)
	}

	if checkErr == nil {
		// Dependency found and working
		result.Found = true
		result.Running = true
		logger.Info("Dependency available", zap.String("dependency", config.Name))
		return result, nil
	}

	// === INFORM: Explain what's missing and why it's needed ===
	logger.Warn("Dependency not found",
		zap.String("dependency", config.Name),
		zap.Error(checkErr))

	result.Found = false

	// Display clear information to user
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: Missing Dependency", zap.String("name", config.Name))
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: What it does", zap.String("description", config.Description))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Current status: NOT INSTALLED")
	logger.Info("terminal prompt: ")

	if config.InstallCmd != "" {
		logger.Info("terminal prompt: To install manually, run:")
		logger.Info("terminal prompt:   " + config.InstallCmd)
		logger.Info("terminal prompt: ")
	}

	if config.StartCmd != "" {
		logger.Info("terminal prompt: To start the service, run:")
		logger.Info("terminal prompt:   " + config.StartCmd)
		logger.Info("terminal prompt: ")
	}

	// === CONSENT: Ask user what they want to do ===
	if !config.AutoInstall {
		// Cannot auto-install, just inform user
		logger.Info("terminal prompt: This dependency is required to continue.")
		logger.Info("terminal prompt: Please install it and try again.")
		logger.Info("terminal prompt: ")

		if config.Required {
			errMsg := fmt.Sprintf("%s is required but not installed.\n\n"+
				"What it does: %s\n\n"+
				"To install:\n  %s",
				config.Name,
				config.Description,
				config.InstallCmd)

			if config.StartCmd != "" {
				errMsg += fmt.Sprintf("\n\nTo start:\n  %s", config.StartCmd)
			}

			return result, eos_err.NewUserError("%s", errMsg)
		}

		result.UserDecline = true
		return result, nil
	}

	// Offer to auto-install
	logger.Info("terminal prompt: Would you like Eos to install this for you?")
	logger.Info("terminal prompt: ")

	consent := PromptYesNo(rc.Ctx, fmt.Sprintf("Install %s automatically", config.Name), false)

	if !consent {
		logger.Info("User declined automatic installation", zap.String("dependency", config.Name))
		result.UserDecline = true

		if config.Required {
			return result, eos_err.NewUserError(
				"%s is required but you declined installation.\n\n"+
					"To install manually:\n  %s\n\n"+
					"Then run this command again.",
				config.Name,
				config.InstallCmd)
		}

		return result, nil
	}

	// === INTERVENE: User consented, attempt installation ===
	logger.Info("User consented to automatic installation", zap.String("dependency", config.Name))
	logger.Info("terminal prompt: Installing " + config.Name + "...")

	if err := installDependency(rc, config); err != nil {
		logger.Error("Automatic installation failed",
			zap.String("dependency", config.Name),
			zap.Error(err))

		return result, fmt.Errorf("automatic installation of %s failed: %w\n\n"+
			"Please install manually:\n  %s",
			config.Name, err, config.InstallCmd)
	}

	// === EVALUATE: Verify installation worked ===
	logger.Info("Verifying installation", zap.String("dependency", config.Name))

	if config.CustomCheckFn != nil {
		checkErr = config.CustomCheckFn(rc.Ctx)
	} else {
		checkErr = checkDependencyCommand(rc.Ctx, config.CheckCommand, config.CheckArgs, checkTimeout)
	}

	if checkErr != nil {
		return result, fmt.Errorf("installation appeared to succeed but verification failed: %w\n\n"+
			"Please check manually:\n  %s",
			checkErr, config.CheckCommand)
	}

	result.Found = true
	result.Running = true
	logger.Info("Dependency successfully installed and verified",
		zap.String("dependency", config.Name))
	logger.Info("terminal prompt: ✓ " + config.Name + " is now ready")
	logger.Info("terminal prompt: ")

	return result, nil
}

// checkDependencyCommand checks if a command exists and runs successfully
func checkDependencyCommand(ctx context.Context, command string, args []string, timeout time.Duration) error {
	logger := otelzap.Ctx(ctx)

	// First check if command exists in PATH
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command '%s' not found in PATH", command)
	}

	logger.Debug("Command found in PATH",
		zap.String("command", command),
		zap.String("path", path))

	// If args provided, try running the command with timeout
	if len(args) > 0 {
		checkCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		cmd := exec.CommandContext(checkCtx, command, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("command '%s %v' failed: %w\nOutput: %s",
				command, args, err, string(output))
		}
	}

	return nil
}

// installDependency attempts to install a dependency
// This should only be called after user consent
func installDependency(rc *eos_io.RuntimeContext, config DependencyConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config.InstallCmd == "" {
		return fmt.Errorf("no installation command provided")
	}

	// Set default timeouts if not provided
	installTimeout := config.InstallTimeout
	if installTimeout == 0 {
		installTimeout = DefaultInstallTimeout
	}
	startTimeout := config.StartTimeout
	if startTimeout == 0 {
		startTimeout = DefaultStartTimeout
	}

	logger.Info("Executing installation command",
		zap.String("dependency", config.Name),
		zap.String("command", config.InstallCmd),
		zap.Duration("timeout", installTimeout))

	// Execute installation command
	// StreamOutput: true shows progress to user in real-time (essential for large downloads)
	// This prevents the "hanging" appearance when Ollama downloads 100s of MB
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command:      "/bin/bash",
		Args:         []string{"-c", config.InstallCmd},
		Capture:      false,
		StreamOutput: true, // Show download progress to user
		Timeout:      installTimeout,
	})

	if err != nil {
		return fmt.Errorf("installation command failed: %w", err)
	}

	logger.Info("Installation command completed",
		zap.String("dependency", config.Name))

	// If auto-start is enabled and start command provided, start the service
	if config.AutoStart && config.StartCmd != "" {
		logger.Info("Starting service",
			zap.String("dependency", config.Name),
			zap.String("command", config.StartCmd),
			zap.Duration("timeout", startTimeout))

		_, err := execute.Run(rc.Ctx, execute.Options{
			Command:      "/bin/bash",
			Args:         []string{"-c", config.StartCmd},
			Capture:      false,
			StreamOutput: true, // Show startup messages to user
			Timeout:      startTimeout,
		})

		if err != nil {
			logger.Warn("Failed to start service (may need manual start)",
				zap.String("dependency", config.Name),
				zap.Error(err))
			// Don't fail on start errors - user can start manually
		}
	}

	return nil
}

// PromptDependencyInstall is a simpler helper that just prompts about installation
// Use this when you want manual control over the install process
func PromptDependencyInstall(rc *eos_io.RuntimeContext, name, description, installCmd string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: Missing: " + name)
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: What it does: " + description)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To install:")
	logger.Info("terminal prompt:   " + installCmd)
	logger.Info("terminal prompt: ")

	return PromptYesNo(rc.Ctx, fmt.Sprintf("Install %s now", name), false)
}

// DisplayDependencyError displays a user-friendly error about a missing dependency
// Use this in UserError messages to maintain consistency
func DisplayDependencyError(name, description, installCmd, startCmd string) string {
	msg := fmt.Sprintf("%s is required but not available.\n\n"+
		"What it does: %s\n\n"+
		"To install:\n  %s",
		name, description, installCmd)

	if startCmd != "" {
		msg += fmt.Sprintf("\n\nTo start:\n  %s", startCmd)
	}

	return msg
}

// CheckDependencyInstalled is a simple helper to check if a command exists in PATH
// Returns nil if installed, error if not found
func CheckDependencyInstalled(command string) (string, error) {
	path, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH", command)
	}
	return path, nil
}
