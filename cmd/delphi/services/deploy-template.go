package services

import (
	"os"
	"os/exec"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var deployTemplateCmd = &cobra.Command{
	Use:   "deploy-template",
	Short: "Deploy email template for Delphi emailer service",
	Long: `Deploy the email template required by the delphi-emailer service.

This command:
- Creates the /opt/stackstorm/packs/delphi/ directory structure
- Copies the email.html template from assets/ to the target location
- Sets correct permissions (stanley:stanley 0644)
- Ensures the template is accessible by the delphi-emailer service

The template will be deployed to: /opt/stackstorm/packs/delphi/email.html`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Deploying email template for Delphi emailer service")

		// Check if we have sudo privileges
		if !eos_unix.CanInteractiveSudo() {
			logger.Error(" Sudo privileges required for template deployment")
			return nil
		}

		// Define source and target paths
		sourcePath := "/usr/local/share/eos/assets/email.html"
		targetDir := "/opt/stackstorm/packs/delphi"
		targetPath := filepath.Join(targetDir, "email.html")

		logger.Info(" Template deployment paths",
			zap.String("source", sourcePath),
			zap.String("target", targetPath))

		// Check if source template exists
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			logger.Error(" Source template not found",
				zap.String("path", sourcePath),
				zap.Error(err))
			logger.Info(" The email template should be deployed during 'eos create delphi'")
			return err
		}

		logger.Info(" Source template found", zap.String("path", sourcePath))

		// Create target directory with proper permissions
		logger.Info(" Creating target directory", zap.String("directory", targetDir))

		mkdirCmd := exec.Command("sudo", "mkdir", "-p", targetDir)
		mkdirCmd.Stdout = os.Stdout
		mkdirCmd.Stderr = os.Stderr
		if err := mkdirCmd.Run(); err != nil {
			logger.Error(" Failed to create target directory",
				zap.String("directory", targetDir),
				zap.Error(err))
			return err
		}

		logger.Info(" Target directory created", zap.String("directory", targetDir))

		// Copy template file
		logger.Info(" Copying template file")

		copyCmd := exec.Command("sudo", "cp", sourcePath, targetPath)
		copyCmd.Stdout = os.Stdout
		copyCmd.Stderr = os.Stderr
		if err := copyCmd.Run(); err != nil {
			logger.Error(" Failed to copy template file",
				zap.String("source", sourcePath),
				zap.String("target", targetPath),
				zap.Error(err))
			return err
		}

		// Set ownership and permissions
		chownCmd := exec.Command("sudo", "chown", "stanley:stanley", targetPath)
		if err := chownCmd.Run(); err != nil {
			logger.Warn("Failed to set ownership (non-critical)",
				zap.String("file", targetPath),
				zap.Error(err))
		}

		chmodCmd := exec.Command("sudo", "chmod", "0644", targetPath)
		if err := chmodCmd.Run(); err != nil {
			logger.Warn("Failed to set permissions (non-critical)",
				zap.String("file", targetPath),
				zap.Error(err))
		}

		logger.Info(" Template copied successfully",
			zap.String("target", targetPath))

		// Verify deployment
		if _, err := os.Stat(targetPath); err != nil {
			logger.Warn("Template verification failed",
				zap.String("path", targetPath),
				zap.Error(err))
		} else {
			logger.Info(" Template deployment verified", zap.String("path", targetPath))
		}

		logger.Info(" Email template deployment complete")
		logger.Info(" Next steps:")
		logger.Info("   1. Ensure .env file is configured at /opt/stackstorm/packs/delphi/.env")
		logger.Info("   2. Restart emailer service: eos delphi services restart delphi-emailer")
		logger.Info("   3. Check service status: eos delphi services status delphi-emailer")

		return nil
	}),
}

func init() {
	ServicesCmd.AddCommand(deployTemplateCmd)
}
