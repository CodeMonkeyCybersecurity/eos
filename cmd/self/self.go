// cmd/self/self.go

package self

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/git"
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

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Eos to the latest version",
	Long: `Update Eos to the latest version by pulling from git repository and reinstalling.
This command performs the equivalent of: su, cd /opt/eos && git pull && ./install.sh && exit`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting Eos self-update process")

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

		// Execute git pull
		logger.Info(" Pulling latest changes from git repository")
		gitCmd := exec.Command("git", "pull")
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr
		if err := gitCmd.Run(); err != nil {
			logger.Error(" Git pull failed", zap.Error(err))
			return fmt.Errorf("failed to pull latest changes: %w", err)
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
			logger.Error(" Installation script failed", zap.Error(err))
			return fmt.Errorf("failed to run installation script: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info(" Eos self-update completed successfully")
		otelzap.Ctx(rc.Ctx).Info(" Eos has been successfully updated to the latest version")

		return nil
	}),
}

func init() {
	SelfCmd.AddCommand(updateCmd)
	SelfCmd.AddCommand(NewSecretsCmd())
	SelfCmd.AddCommand(git.GitCmd)
	// Add SelfCmd to ConfigCmd so 'eos config self' works
}
