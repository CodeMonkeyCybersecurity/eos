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
		
		// Check for uncommitted changes and conflicts first
		statusCmd := exec.Command("git", "status", "--porcelain")
		statusOutput, err := statusCmd.CombinedOutput()
		if err != nil {
			logger.Error("Failed to check git status", zap.Error(err), zap.String("output", string(statusOutput)))
			return fmt.Errorf("failed to check git status: %w - output: %s", err, string(statusOutput))
		}

		// Check for merge conflicts
		conflictCmd := exec.Command("git", "diff", "--name-only", "--diff-filter=U")
		conflictOutput, _ := conflictCmd.Output()
		if len(conflictOutput) > 0 {
			logger.Warn("Unresolved merge conflicts detected", 
				zap.String("conflicts", string(conflictOutput)))
			logger.Info("\n" + 
				"❌ Cannot update - there are unresolved merge conflicts.\n" +
				"Please resolve them manually with these steps:\n" +
				"1. Resolve the conflicts marked in these files:\n   " + 
				strings.ReplaceAll(string(conflictOutput), "\n", "\n   ") + "\n" +
				"2. Mark them as resolved: git add <file>\n" +
				"3. Complete the merge: git commit\n" +
				"4. Try updating again: sudo eos self update")
			return fmt.Errorf("unresolved merge conflicts detected")
		}

		// If there are uncommitted changes, stash them
		var stashed bool
		if len(statusOutput) > 0 {
			logger.Info("Detected uncommitted changes, stashing them")
			stashSave := exec.Command("git", "stash", "save", "--include-untracked", "--keep-index", 
				"eos-self-update-auto-stash")
			stashSave.Stdout = os.Stdout
			stashSave.Stderr = os.Stderr
			
			if err := stashSave.Run(); err != nil {
				// Check if stashing failed because there were no changes to stash
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
					// Git returns 1 when there's nothing to stash
					logger.Debug("No changes to stash")
				} else {
					logger.Error("Failed to stash changes", zap.Error(err))
					return fmt.Errorf("failed to stash uncommitted changes: %w", err)
				}
			} else {
				stashed = true
			}
		}

		// Execute git fetch first to avoid merge issues
		logger.Info("Fetching latest changes from remote...")
		fetchCmd := exec.Command("git", "fetch", "--all", "--prune")
		fetchCmd.Stdout = os.Stdout
		fetchCmd.Stderr = os.Stderr
		if err := fetchCmd.Run(); err != nil {
			logger.Error("Git fetch failed", zap.Error(err))
			return fmt.Errorf("failed to fetch latest changes: %w", err)
		}

		// Check if we can fast-forward
		logger.Info("Checking if we can fast-forward...")
		aheadCmd := exec.Command("git", "rev-list", "--count", "--left-right", "HEAD...@{u}")
		aheadOutput, _ := aheadCmd.Output()
		
		// Execute git pull with rebase to avoid merge commits
		logger.Info("Pulling latest changes with rebase...")
		pullCmd := exec.Command("git", "pull", "--rebase")
		pullCmd.Stdout = os.Stdout
		pullCmd.Stderr = os.Stderr
		
		if err := pullCmd.Run(); err != nil {
			logger.Error("Git pull with rebase failed", zap.Error(err))
			
			// Check for merge conflicts
			conflictCmd := exec.Command("git", "diff", "--name-only", "--diff-filter=U")
			conflictOutput, _ := conflictCmd.Output()
			
			if len(conflictOutput) > 0 {
				// Abort the rebase
				exec.Command("git", "rebase", "--abort").Run()
				
				logger.Error("\n❌ Merge conflict detected during update",
					zap.String("conflicting_files", string(conflictOutput)))
				
				// Provide recovery instructions
				logger.Info("\nTo resolve this issue:\n" +
					"1. Resolve the conflicts in these files:\n   " +
					strings.ReplaceAll(string(conflictOutput), "\n", "\n   ") + "\n" +
					"2. Mark them as resolved: git add <file>\n" +
					"3. Continue the rebase: git rebase --continue\n" +
					"4. Try updating again: sudo eos self update\n\n" +
					"Or to reset to a clean state (WARNING: discards local changes):\n" +
					"  git reset --hard HEAD && git clean -fd")
				
				return fmt.Errorf("merge conflict during update")
			}
			
			// For other git errors, try a regular pull
			logger.Warn("Rebase failed, attempting regular pull...")
			pullCmd = exec.Command("git", "pull")
			pullCmd.Stdout = os.Stdout
			pullCmd.Stderr = os.Stderr
			
			if err := pullCmd.Run(); err != nil {
				logger.Error("Regular git pull also failed", zap.Error(err))
				return fmt.Errorf("failed to pull changes: %w", err)
			}
		}

		// If we stashed changes, pop them back
		if stashed {
			logger.Info("Restoring stashed changes...")
			// First check if there are any stashes
			stashList := exec.Command("git", "stash", "list")
			stashListOutput, _ := stashList.Output()
			
			if len(stashListOutput) > 0 {
				popCmd := exec.Command("git", "stash", "pop", "--index")
				popCmd.Stdout = os.Stdout
				popCmd.Stderr = os.Stderr
				
				if err := popCmd.Run(); err != nil {
					// If pop fails, try apply instead and drop the stash
					logger.Warn("Stash pop failed, trying stash apply...")
					applyCmd := exec.Command("git", "stash", "apply")
					applyCmd.Stdout = os.Stdout
					applyCmd.Stderr = os.Stderr
					
					if applyErr := applyCmd.Run(); applyErr != nil {
						logger.Error("Failed to restore stashed changes", 
							zap.Error(applyErr), 
							zap.String("recovery_cmd", "git stash apply"))
					} else {
						// Drop the stash since we applied it
						dropCmd := exec.Command("git", "stash", "drop")
						dropCmd.Stdout = os.Stdout
						dropCmd.Stderr = os.Stderr
						_ = dropCmd.Run()
					}
				}
			}

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
