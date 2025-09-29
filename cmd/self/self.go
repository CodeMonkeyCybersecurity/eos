// cmd/self/self.go

package self

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/ai"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/test"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var SelfCmd = &cobra.Command{
	Use:   "self",
	Short: "Self-management commands for Eos",
	Long: `The self command provides utilities for managing the Eos installation itself.
	Including telemetry, authentication, environment defaults, and other Eos behaviors.`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help()
		return nil
	}),
}

var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Eos to the latest version",
	Long: `Update Eos to the latest version by pulling from git repository and reinstalling.
This command performs the equivalent of: su, cd /opt/eos && git pull && ./install.sh && exit`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Declare variables that will be used later
		var resetCmd *exec.Cmd
		var cleanCmd *exec.Cmd
		
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Eos self-update process")

		// Phase 1: ASSESS - Check prerequisites and current state
		logger.Info("Phase 1: ASSESS - Checking prerequisites")
		
		// Check if we're already running as root
		if os.Geteuid() != 0 {
			return eos_err.NewExpectedError(rc.Ctx, errors.New("self-update must be run as root. Please run: sudo eos self update (or sudo eos config self update)"))
		}

		// Check if /opt/eos directory exists
		if _, err := os.Stat("/opt/eos"); os.IsNotExist(err) {
			return eos_err.NewExpectedError(rc.Ctx, errors.New("/opt/eos directory not found. Please ensure Eos is installed in /opt/eos"))
		}

		// Change to /opt/eos directory
		if err := os.Chdir("/opt/eos"); err != nil {
			logger.Error(" Failed to change directory",
				zap.String("directory", "/opt/eos"),
				zap.Error(err))
			return fmt.Errorf("failed to change to /opt/eos directory: %w", err)
		}

		logger.Info(" Changed to /opt/eos directory")

		// Phase 2: INTERVENE - Perform the update operations
		logger.Info("Phase 2: INTERVENE - Performing update operations")

		// Reset any local changes to match the remote exactly
		logger.Info("Resetting local changes to match remote...")
		resetCmd = exec.Command("git", "reset", "--hard", "HEAD")
		resetCmd.Stdout = os.Stdout
		resetCmd.Stderr = os.Stderr
		if err := resetCmd.Run(); err != nil {
			logger.Error("Failed to reset local changes", zap.Error(err))
			return fmt.Errorf("failed to reset local changes: %w", err)
		}

		// Clean untracked files and directories
		cleanCmd = exec.Command("git", "clean", "-fd")
		cleanCmd.Stdout = os.Stdout
		cleanCmd.Stderr = os.Stderr
		if err := cleanCmd.Run(); err != nil {
			logger.Error("Failed to clean untracked files", zap.Error(err))
			return fmt.Errorf("failed to clean untracked files: %w", err)
		}

		// Clean any leftover git merge/rebasing artifacts
		resetMergeCmd := exec.Command("git", "merge", "--abort")
		_ = resetMergeCmd.Run() // Ignore errors as this will fail if not in a merge

		rebaseAbortCmd := exec.Command("git", "rebase", "--abort")
		_ = rebaseAbortCmd.Run() // Ignore errors as this will fail if not in a rebase

		// Clean up any leftover .orig files from merges
		cleanOrigCmd := exec.Command("find", ".", "-name", "*.orig", "-delete")
		_ = cleanOrigCmd.Run()

		// Fetch the latest changes from all remotes
		logger.Info("Fetching latest changes from all remotes...")
		fetchCmd := exec.Command("git", "fetch", "--all", "--prune")
		fetchCmd.Stdout = os.Stdout
		fetchCmd.Stderr = os.Stderr
		if err := fetchCmd.Run(); err != nil {
			logger.Error("Git fetch failed", zap.Error(err))
			return fmt.Errorf("failed to fetch latest changes: %w", err)
		}

		// Reset to match the remote branch exactly
		logger.Info("Resetting to match remote origin/main...")
		resetCmd = exec.Command("git", "reset", "--hard", "origin/main")
		resetCmd.Stdout = os.Stdout
		resetCmd.Stderr = os.Stderr
		if err := resetCmd.Run(); err != nil {
			logger.Error("Failed to reset to origin/main", zap.Error(err))
			return fmt.Errorf("failed to reset to origin/main: %w", err)
		}

		// Clean any remaining untracked files
		cleanCmd = exec.Command("git", "clean", "-fd")
		cleanCmd.Stdout = os.Stdout
		cleanCmd.Stderr = os.Stderr
		if err := cleanCmd.Run(); err != nil {
			logger.Error("Failed to clean repository", zap.Error(err))
			return fmt.Errorf("failed to clean repository: %w", err)
		}

		// Verify we're on the latest commit
		revParseCmd := exec.Command("git", "rev-parse", "HEAD")
		revOutput, _ := revParseCmd.Output()
		logger.Info("Successfully updated to latest commit", 
			zap.String("commit", strings.TrimSpace(string(revOutput))))

		// Clear any existing stashes to prevent conflicts
		logger.Info("Clearing any existing stashes...")
		stashClearCmd := exec.Command("git", "stash", "clear")
		stashClearCmd.Stdout = os.Stdout
		stashClearCmd.Stderr = os.Stderr
		_ = stashClearCmd.Run()

		// Check if install.sh exists and is executable
		if _, err := os.Stat("./install.sh"); os.IsNotExist(err) {
			return eos_err.NewExpectedError(rc.Ctx, errors.New("install.sh not found in /opt/eos. Please ensure the installation script is present"))
		}

		// Execute install.sh
		logger.Info(" Running installation script")
		installCmd := exec.Command("./install.sh")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			// Check if this is a dpkg lock error
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 100 {
				// Check if apt/dpkg is currently running
				checkCmd := exec.Command("sh", "-c", "lsof /var/lib/dpkg/lock-frontend 2>/dev/null | grep -v COMMAND | awk '{print $2}' | head -1")
				if pidBytes, err := checkCmd.Output(); err == nil && len(pidBytes) > 0 {
					pid := string(pidBytes[:len(pidBytes)-1]) // Remove newline
					
					// Get the process name
					psCmd := exec.Command("ps", "-p", pid, "-o", "comm=")
					if nameBytes, err := psCmd.Output(); err == nil && len(nameBytes) > 0 {
						processName := string(nameBytes[:len(nameBytes)-1])
						
						logger.Warn(" Another package management process is running",
							zap.String("process", processName),
							zap.String("pid", pid))
						
						logger.Info("terminal prompt: ")
						logger.Info("terminal prompt: ⚠️  Another package management process is currently running")
						logger.Info("terminal prompt: Process details", 
							zap.String("process", processName),
							zap.String("pid", pid))
						logger.Info("terminal prompt: ")
						logger.Info("terminal prompt: Please wait for it to complete, then run:")
						logger.Info("terminal prompt:   sudo eos self update")
						logger.Info("terminal prompt: ")
						logger.Info("terminal prompt: Or skip the system update with:")
						logger.Info("terminal prompt:   cd /opt/eos && sudo ./install.sh --skip-update")
						logger.Info("terminal prompt: ")
						logger.Info("terminal prompt: If the process is stuck, you can check it with:")
						logger.Info("terminal prompt:   ps -p [PID] -f", zap.String("pid", pid))
						
						return eos_err.NewUserError("cannot update while another package manager is running")
					}
				}
				
				// Generic dpkg lock error message
				logger.Warn(" Package management system is locked")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: ⚠️  The package management system is currently locked")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: This usually means:")
				logger.Info("terminal prompt:   • Another apt/dpkg process is running")
				logger.Info("terminal prompt:   • An automatic update is in progress")
				logger.Info("terminal prompt:   • A previous installation was interrupted")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: To check what's using apt/dpkg:")
				logger.Info("terminal prompt:   sudo lsof /var/lib/dpkg/lock-frontend")
				logger.Info("terminal prompt:   ps aux | grep -E 'apt|dpkg'")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: Once resolved, run:")
				logger.Info("terminal prompt:   sudo eos self update")
				
				return eos_err.NewUserError("package management system is locked")
			}
			
			// For other errors, provide helpful context
			logger.Error(" Installation script failed", zap.Error(err))
			
			// Check if this might be a network issue
			if exitErr, ok := err.(*exec.ExitError); ok {
				switch exitErr.ExitCode() {
				case 1:
					logger.Info("terminal prompt: ")
					logger.Info("terminal prompt: ❌ Installation failed - this might be a general error")
					logger.Info("terminal prompt: Check the output above for specific error messages")
				case 2:
					logger.Info("terminal prompt: ")
					logger.Info("terminal prompt: ❌ Installation failed - command not found or permission denied")
					logger.Info("terminal prompt: Ensure all required tools are installed")
				default:
					logger.Info("terminal prompt: ")
					logger.Info("terminal prompt: ❌ Installation failed with exit code", zap.Int("exit_code", exitErr.ExitCode()))
					logger.Info("terminal prompt: Check the output above for details")
				}
			}
			
			return fmt.Errorf("failed to run installation script: %w", err)
		}

		// Phase 3: EVALUATE - Verify the update was successful
		logger.Info("Phase 3: EVALUATE - Verifying update success")
		
		// Check if eos binary exists and is executable
		if _, err := exec.LookPath("eos"); err != nil {
			logger.Error("Failed to find eos binary after update", zap.Error(err))
			return fmt.Errorf("update appears to have failed - eos binary not found: %w", err)
		}
		
		logger.Info(" Eos self-update completed successfully")
		logger.Info(" Eos has been successfully updated to the latest version")

		return nil
	}),
}

func init() {
	SelfCmd.AddCommand(UpdateCmd)
	SelfCmd.AddCommand(SecretsCmd)
	SelfCmd.AddCommand(gitCmd)
	SelfCmd.AddCommand(ai.AICmd)
	SelfCmd.AddCommand(test.TestCmd)
	SelfCmd.AddCommand(TelemetryCmd)
	SelfCmd.AddCommand(EnrollCmd)
	// Add SelfCmd to ConfigCmd so 'eos config self' works
}
