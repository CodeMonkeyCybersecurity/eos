diff --git a/cmd/self/self.go b/cmd/self/self.go
index 0000000..0000001 100644
--- a/cmd/self/self.go
+++ b/cmd/self/self.go
@@ -1,17 +1,33 @@
 package self

 import (
+	"context"
 	"errors"
 	"fmt"
 	"os"
 	"os/exec"
 	"strings"
+	"syscall"
+	"time"

 	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/ai"
 	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/test"
 	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
 	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
 	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
+	"github.com/CodeMonkeyCybersecurity/eos/pkg/security"
 	"github.com/spf13/cobra"
 	"github.com/uptrace/opentelemetry-go-extra/otelzap"
 	"go.uber.org/zap"
 )
 
+var (
+	updateAggressiveClean bool     // -fdx instead of -fd
+	updatePreserve        []string // patterns to preserve when aggressive
+	updateSkipSystem      bool     // pass-through to install.sh if you want skip
+	updateSkipBuild       bool     // developer option; still runs git steps
+)
+
 var SelfCmd = &cobra.Command{
 	Use:   "self",
 	Short: "Self-management commands for Eos",
@@ -26,25 +42,245 @@ var SelfCmd = &cobra.Command{
 	}),
 }
 
 var UpdateCmd = &cobra.Command{
 	Use:   "update",
 	Short: "Update Eos to the latest version",
-	Long: `Update Eos to the latest version by pulling from git repository and reinstalling.
-This command performs the equivalent of: su, cd /opt/eos && git pull && ./install.sh && exit`,
+	Long: `Update Eos to the latest version by force-syncing /opt/eos to origin/main and reinstalling.
+Default strategy DISCARD-LOCAL: hard-reset to origin/main, do not stash-pop, and clean untracked files.
+This avoids conflicts and ensures deterministic updates on managed hosts.`,
 
 	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
-		otelzap.Ctx(rc.Ctx).Info("Starting Eos self-update process")
+		l := otelzap.Ctx(rc.Ctx)
+		l.Info("Starting Eos self-update process")
 
 		// Phase 1: ASSESS - Check prerequisites and current state
-		logger := otelzap.Ctx(rc.Ctx)
-		logger.Info("Phase 1: ASSESS - Checking prerequisites")
+		l.Info("Phase 1: ASSESS - Checking prerequisites")
 
 		// Check if we're already running as root
 		if os.Geteuid() != 0 {
 			return eos_err.NewExpectedError(rc.Ctx, errors.New("self-update must be run as root. Please run: sudo eos self update"))
 		}
 
+		// Single-run lock to avoid overlapping updates
+		lockPath := "/var/run/eos-self-update.lock"
+		lockFd, lockErr := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR, 0600)
+		if lockErr != nil {
+			l.Warn("Could not open lock file", zap.String("path", lockPath), zap.Error(lockErr))
+		} else {
+			if err := syscall.Flock(lockFd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
+				return eos_err.NewUserError("another eos self update is currently running (lock held); try again in a minute")
+			}
+			defer func() {
+				_ = syscall.Flock(lockFd, syscall.LOCK_UN)
+				_ = syscall.Close(lockFd)
+				_ = os.Remove(lockPath)
+			}()
+		}
+
 		// Check if /opt/eos directory exists
 		if _, err := os.Stat("/opt/eos"); os.IsNotExist(err) {
 			return eos_err.NewExpectedError(rc.Ctx, errors.New("/opt/eos directory not found. Please ensure Eos is installed in /opt/eos"))
 		}
 
 		// Change to /opt/eos directory
-		if err := os.Chdir("/opt/eos"); err != nil {
-			logger.Error(" Failed to change directory",
+		if err := os.Chdir("/opt/eos"); err != nil {
+			l.Error("Failed to change directory",
 				zap.String("directory", "/opt/eos"),
 				zap.Error(err))
 			return fmt.Errorf("failed to change to /opt/eos directory: %w", err)
 		}
 
-		logger.Info(" Changed to /opt/eos directory")
+		l.Info("Changed to /opt/eos directory")
+
+		// Verify git repo
+		if err := run(rc.Ctx, l, "git", "rev-parse", "--is-inside-work-tree"); err != nil {
+			return eos_err.NewExpectedError(rc.Ctx, errors.New("/opt/eos is not a git repository; reinstall Eos or clone the repo there"))
+		}
+
+		// Handle stale lock
+		if _, err := os.Stat(".git/index.lock"); err == nil {
+			// If no git process holds the lock, remove it
+			psErr := run(rc.Ctx, l, "bash", "-lc", "pgrep -fa 'git' >/dev/null || rm -f .git/index.lock")
+			if psErr != nil {
+				l.Warn("Possible stale git index.lock; could not auto-clear", zap.Error(psErr))
+			} else {
+				l.Info("Cleared stale .git/index.lock (no active git process found)")
+			}
+		}
+
+		// Abort any in-progress merge/rebase/cherry
+		_ = run(rc.Ctx, l, "git", "merge", "--abort")
+		_ = run(rc.Ctx, l, "git", "rebase", "--abort")
+		_ = run(rc.Ctx, l, "git", "cherry-pick", "--abort")
+
+		// Fetch & force reset to origin/main (deterministic)
+		l.Info("Fetching latest changes from origin...")
+		if err := run(rc.Ctx, l, "git", "fetch", "--all", "--prune"); err != nil {
+			return fmt.Errorf("failed to fetch latest changes: %w", err)
+		}
+		l.Info("Resetting worktree to origin/main (discarding local changes)")
+		if err := run(rc.Ctx, l, "git", "reset", "--hard", "origin/main"); err != nil {
+			return fmt.Errorf("failed to reset to origin/main: %w", err)
+		}
+
+		// Clean untracked files
+		if updateAggressiveClean {
+			args := []string{"clean", "-fdx"}
+			for _, p := range updatePreserve {
+				args = append(args, "-e", p)
+			}
+			l.Info("Cleaning untracked & ignored files", zap.Strings("preserve", updatePreserve))
+			if err := run(rc.Ctx, l, "git", args...); err != nil {
+				return fmt.Errorf("failed to clean repository (-fdx): %w", err)
+			}
+		} else {
+			l.Info("Cleaning untracked files only (-fd)")
+			if err := run(rc.Ctx, l, "git", "clean", "-fd"); err != nil {
+				return fmt.Errorf("failed to clean repository (-fd): %w", err)
+			}
+		}
+
+		// DO NOT stash-pop automatically (that caused your dryrun.go conflict)
+		// If a stash exists, tell the user but keep it.
+		if err := run(rc.Ctx, l, "bash", "-lc", "git stash list | sed -n '1p'"); err == nil {
+			l.Warn("Stash entries detected; not applying them during update. You can manually apply with: git stash pop (may conflict).")
+		}
 
 		// Phase 2: INTERVENE - Perform the update operations
-		logger.Info("Phase 2: INTERVENE - Performing update operations")
+		l.Info("Phase 2: INTERVENE - Performing update operations")
 
-		// Reset any local changes to match the remote exactly
-		logger.Info("Resetting local changes to match remote...")
-		resetCmd = exec.Command("git", "reset", "--hard", "HEAD")
-		resetCmd.Stdout = os.Stdout
-		resetCmd.Stderr = os.Stderr
-		if err := resetCmd.Run(); err != nil {
-			logger.Error("Failed to reset local changes", zap.Error(err))
-			return fmt.Errorf("failed to reset local changes: %w", err)
-		}
+		// Run install.sh (with optional pass-through)
+		if updateSkipBuild {
+			l.Info("Skipping build as requested (--no-build)")
+		} else {
+			l.Info("Running installation script")
+			args := []string{"./install.sh"}
+			if updateSkipSystem {
+				args = append(args, "--skip-update")
+			}
+			if err := run(rc.Ctx, l, args[0], args[1:]...); err != nil {
+				// Install-time dpkg lock handling is already inside install.sh;
+				// here we just surface the error.
+				l.Error("Installation script failed", zap.Error(err))
+				return fmt.Errorf("failed to run installation script: %w", err)
+			}
+		}
 
 		// Phase 3: EVALUATE - Verify the update was successful
-		logger.Info("Phase 3: EVALUATE - Verifying update success")
+		l.Info("Phase 3: EVALUATE - Verifying update success")
 
 		// Check if eos binary exists and is executable
 		if _, err := exec.LookPath("eos"); err != nil {
-			logger.Error("Failed to find eos binary after update", zap.Error(err))
+			l.Error("Failed to find eos binary after update", zap.Error(err))
 			return fmt.Errorf("update appears to have failed - eos binary not found: %w", err)
 		}
 
-		logger.Info(" Eos self-update completed successfully")
-		logger.Info(" Eos has been successfully updated to the latest version")
+		l.Info("Eos self-update completed successfully")
+		l.Info("Eos has been successfully updated to the latest version")
 
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
+
+	// flags
+	UpdateCmd.Flags().BoolVar(&updateAggressiveClean, "aggressive-clean", false, "Use git clean -fdx (also removes ignored files).")
+	UpdateCmd.Flags().StringSliceVar(&updatePreserve, "preserve", nil, "Patterns to preserve when using --aggressive-clean (passed as multiple -e PATTERN to git clean).")
+	UpdateCmd.Flags().BoolVar(&updateSkipSystem, "skip-system-update", false, "Pass --skip-update to install.sh (skip apt).")
+	UpdateCmd.Flags().BoolVar(&updateSkipBuild, "no-build", false, "Skip install.sh build step (advanced).")
 }
+
+// run executes a command with context, logs it, and streams stdio through.
+func run(ctx context.Context, l *otelzap.Logger, name string, args ...string) error {
+	l.Info("exec", zap.String("cmd", name), zap.Strings("args", args))
+	c := exec.CommandContext(ctx, name, args...)
+	c.Stdout = os.Stdout
+	c.Stderr = os.Stderr
+	// Harden PATH for safety (drop current dir)
+	c.Env = security.PrunedEnv(os.Environ())
+	return c.Run()
+}