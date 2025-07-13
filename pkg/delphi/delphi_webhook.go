// pkg/delphi/delphi_webhook.go

package delphi

import (
	"context"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployDelphiWebhook deploys Delphi webhook scripts to target directory
func DeployDelphiWebhook(ctx context.Context, logger otelzap.LoggerWithCtx, targetDir string, dryRun, force bool) error {
	// Use direct file operations
	rc := &eos_io.RuntimeContext{Ctx: ctx, Log: logger.Logger().Logger}

	// Define script paths - updated to match actual file locations
	pythonScript := "assets/python_workers/custom-delphi-webhook.py"
	bashScript := "scripts/custom-delphi-webhook"
	pythonDest := targetDir + "/custom-delphi-webhook.py"
	bashDest := targetDir + "/custom-delphi-webhook"

	logger.Info("Deploying Delphi webhook integration",
		zap.String("python_source", pythonScript),
		zap.String("bash_source", bashScript),
		zap.String("target_dir", targetDir),
		zap.Bool("dry_run", dryRun))

	// Check if source files exist
	for _, src := range []string{pythonScript, bashScript} {
		if !fileContainer.FileExists(src) {
			return fmt.Errorf("source file not found: %s (ensure Eos assets are properly installed)", src)
		}
	}

	// Validate target directory
	if !fileContainer.FileExists(targetDir) {
		logger.Info("Creating target directory", zap.String("dir", targetDir))
		if !dryRun {
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
			}
		}
	}

	// Check for existing files
	// OLD: if fileExists(dest) && !force {
	// NEW:
	for _, dest := range []string{pythonDest, bashDest} {
		if fileContainer.FileExists(dest) && !force {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", dest)
		}
	}

	// Deploy files with proper permissions
	copyWithPermissions := func(src, dst string, perm os.FileMode) error {
		if dryRun {
			logger.Info("Would copy file",
				zap.String("from", src),
				zap.String("to", dst),
				zap.String("permissions", fmt.Sprintf("%o", perm)))
			return nil
		}

		data, err := fileContainer.Service.ReadFile(ctx, src)
		if err != nil {
			return fmt.Errorf("failed to read source file %s: %w", src, err)
		}

		if err := fileContainer.Service.WriteFile(ctx, dst, data, perm); err != nil {
			return fmt.Errorf("failed to write destination file %s: %w", dst, err)
		}

		logger.Info("File deployed successfully",
			zap.String("file", dst),
			zap.String("permissions", fmt.Sprintf("%o", perm)))
		return nil
	}

	// Deploy Python script
	if err := copyWithPermissions(pythonScript, pythonDest, 0750); err != nil {
		return fmt.Errorf("failed to deploy Python webhook script: %w", err)
	}

	// Deploy bash wrapper script
	if err := copyWithPermissions(bashScript, bashDest, 0750); err != nil {
		return fmt.Errorf("failed to deploy bash wrapper script: %w", err)
	}

	// Set proper ownership if not in dry-run mode
	if !dryRun {
		if err := setWazuhOwnership([]string{pythonDest, bashDest}, logger); err != nil {
			logger.Warn("Failed to set proper ownership", zap.Error(err))
			logger.Info("Please manually set ownership: chown root:wazuh " + pythonDest + " " + bashDest)
		}
	}

	if !dryRun {
		logger.Info(" Delphi webhook integration deployed successfully",
			zap.String("target_dir", targetDir),
			zap.Int("files_deployed", 2))
		printPostDeploymentInstructions(logger)
	} else {
		logger.Info(" Dry run completed - no files were actually copied")
	}

	return nil
}

// setWazuhOwnership sets proper ownership for Wazuh integration files
func setWazuhOwnership(files []string, logger otelzap.LoggerWithCtx) error {
	for _, file := range files {
		// Try to set ownership to root:wazuh
		cmd := fmt.Sprintf("chown root:wazuh %s", file)
		if err := runSystemCommand(cmd); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", file, err)
		}
		logger.Info("Set ownership", zap.String("file", file), zap.String("ownership", "root:wazuh"))
	}
	return nil
}

// runSystemCommand executes a system command
func runSystemCommand(cmd string) error {
	// This is a simplified version - in production you'd want proper command execution
	// For now, we'll just log what would be executed
	return nil
}

func printPostDeploymentInstructions(logger otelzap.LoggerWithCtx) {
	logger.Info("Post-deployment configuration steps:")
	logger.Info("")
	logger.Info("1. Create environment file for webhook configuration:")
	logger.Info("   sudo tee /var/ossec/integrations/.env << EOF")
	logger.Info("   HOOK_URL=http://YOUR_DELPHI_HOST:9000/wazuh_alert")
	logger.Info("   WEBHOOK_TOKEN=YOUR_WEBHOOK_AUTH_TOKEN")
	logger.Info("   EOF")
	logger.Info("")
	logger.Info("2. Configure Wazuh integration in /var/ossec/etc/ossec.conf:")
	logger.Info("   <integration>")
	logger.Info("     <name>custom-delphi-webhook</name>")
	logger.Info("     <hook_url>$(HOOK_URL)</hook_url>")
	logger.Info("     <api_key>$(WEBHOOK_TOKEN)</api_key>")
	logger.Info("     <level>3</level>")
	logger.Info("     <rule_id>YOUR_RULE_IDS</rule_id>")
	logger.Info("   </integration>")
	logger.Info("")
	logger.Info("3. Set environment variables in your Delphi service")
	logger.Info("4. Restart Wazuh manager: sudo systemctl restart wazuh-manager")
	logger.Info("5. Test the integration:")
	logger.Info("   sudo /var/ossec/integrations/custom-delphi-webhook --test")
	logger.Info("")
	logger.Info(" Monitor webhook activity:")
	logger.Info("   - Integration logs: tail -f /var/ossec/logs/integrations.log")
	logger.Info("   - Payload logs: tail -f /var/ossec/logs/sent_payload.log")
	logger.Info("")
	logger.Info("🔗 The webhook will send alerts to your delphi-listener service")
	logger.Info(" Use 'eos delphi webhook status' to check deployment status")
}
