// cmd/create/delphi_webhook.go
package create

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	CreateCmd.AddCommand(NewDelphiWebhookCmd())
}

// NewDelphiWebhookCmd creates the delphi-webhook command
func NewDelphiWebhookCmd() *cobra.Command {
	var (
		targetDir    string
		dryRun       bool
		forceInstall bool
	)

	cmd := &cobra.Command{
		Use:   "delphi-webhook",
		Short: "Deploy Delphi webhook integration scripts to Wazuh",
		Long: `Deploy the custom Delphi webhook integration scripts to Wazuh server.

This command deploys two files to /var/ossec/integrations/:
- custom-delphi-webhook (bash wrapper script)
- custom-delphi-webhook.py (Python webhook implementation)

The scripts are deployed with proper ownership (root:wazuh) and permissions (0750).

After deployment, you need to:
1. Configure /var/ossec/etc/ossec.conf with the webhook integration
2. Restart Wazuh manager to activate the integration

Example:
  eos create delphi-webhook
  eos create delphi-webhook --target-dir /custom/path --dry-run`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Starting Delphi webhook deployment",
				zap.String("target_dir", targetDir),
				zap.Bool("dry_run", dryRun),
				zap.Bool("force", forceInstall))

			return deployDelphiWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
		}),
	}

	cmd.Flags().StringVarP(&targetDir, "target-dir", "t", "/var/ossec/integrations", "Target directory for webhook scripts")
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be done without making changes")
	cmd.Flags().BoolVarP(&forceInstall, "force", "f", false, "Overwrite existing files")

	return cmd
}

func deployDelphiWebhook(ctx context.Context, logger otelzap.LoggerWithCtx, targetDir string, dryRun, force bool) error {
	// Get source files from assets
	eosRoot := os.Getenv("EOS_ROOT")
	if eosRoot == "" {
		// Try to detect from current working directory or binary location
		if pwd, err := os.Getwd(); err == nil && fileExists(filepath.Join(pwd, "assets")) {
			eosRoot = pwd
		} else {
			return fmt.Errorf("EOS_ROOT environment variable not set and cannot auto-detect Eos directory")
		}
	}

	assetsDir := filepath.Join(eosRoot, "assets")
	scriptsDir := filepath.Join(eosRoot, "scripts")

	// Source files
	pythonScript := filepath.Join(assetsDir, "python_workers", "custom-delphi-webhook.py")
	bashScript := filepath.Join(scriptsDir, "custom-delphi-webhook")

	// Destination files
	pythonDest := filepath.Join(targetDir, "custom-delphi-webhook.py")
	bashDest := filepath.Join(targetDir, "custom-delphi-webhook")

	// Validate source files exist
	for _, src := range []string{pythonScript, bashScript} {
		if !fileExists(src) {
			return fmt.Errorf("source file not found: %s", src)
		}
	}

	logger.Info(" Source files located",
		zap.String("python_script", pythonScript),
		zap.String("bash_script", bashScript))

	// Check if target directory exists
	if !fileExists(targetDir) {
		return fmt.Errorf("target directory does not exist: %s (is this a Wazuh server?)", targetDir)
	}

	// Check for existing files
	for _, dest := range []string{pythonDest, bashDest} {
		if fileExists(dest) && !force {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", dest)
		}
	}

	if dryRun {
		logger.Info(" DRY RUN - would perform the following actions:")
		logger.Info(" Copy files:",
			zap.String("python", fmt.Sprintf("%s → %s", pythonScript, pythonDest)),
			zap.String("bash", fmt.Sprintf("%s → %s", bashScript, bashDest)))
		logger.Info(" Set ownership: root:wazuh")
		logger.Info(" Set permissions: 0750")
		return nil
	}

	// Deploy files
	logger.Info(" Copying webhook scripts...")

	// Copy Python script
	if err := copyFile(pythonScript, pythonDest); err != nil {
		return fmt.Errorf("failed to copy Python script: %w", err)
	}
	logger.Info(" Python script deployed", zap.String("path", pythonDest))

	// Copy bash script
	if err := copyFile(bashScript, bashDest); err != nil {
		return fmt.Errorf("failed to copy bash script: %w", err)
	}
	logger.Info(" Bash script deployed", zap.String("path", bashDest))

	// Set ownership and permissions
	logger.Info(" Setting ownership and permissions...")

	files := []string{pythonDest, bashDest}
	for _, file := range files {
		// Set ownership to root:wazuh
		_, err := execute.Run(ctx, execute.Options{
			Command: "chown",
			Args:    []string{"root:wazuh", file},
		})
		if err != nil {
			logger.Warn("Failed to set ownership (continuing)",
				zap.String("file", file),
				zap.Error(err))
		}

		// Set permissions to 0750
		_, err = execute.Run(ctx, execute.Options{
			Command: "chmod",
			Args:    []string{"0750", file},
		})
		if err != nil {
			logger.Warn("Failed to set permissions (continuing)",
				zap.String("file", file),
				zap.Error(err))
		}
	}

	logger.Info(" Delphi webhook scripts deployed successfully")

	// Print post-deployment instructions
	printPostDeploymentInstructions(logger)

	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0750)
	if err != nil {
		return err
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func printPostDeploymentInstructions(logger otelzap.LoggerWithCtx) {
	logger.Info(" Post-deployment configuration required:")
	logger.Info("")
	logger.Info("1. Configure Wazuh integration in /var/ossec/etc/ossec.conf:")
	logger.Info("")
	logger.Info("   <integration>")
	logger.Info("     <name>custom-delphi-webhook</name>")
	logger.Info("     <hook_url>http://YOUR_DELPHI_HOST:9000/wazuh_alert</hook_url>")
	logger.Info("     <api_key>YOUR_WEBHOOK_AUTH_TOKEN</api_key>")
	logger.Info("     <level>3</level>")
	logger.Info("     <rule_id>YOUR_RULE_IDS</rule_id>")
	logger.Info("   </integration>")
	logger.Info("")
	logger.Info("2. Set the WEBHOOK_AUTH_TOKEN in your Delphi environment")
	logger.Info("3. Restart Wazuh manager: systemctl restart wazuh-manager")
	logger.Info("4. Test the integration with: /var/ossec/integrations/custom-delphi-webhook --test")
	logger.Info("")
	logger.Info("🔗 The webhook now sends alerts to your delphi-listener service with proper authentication")
}
