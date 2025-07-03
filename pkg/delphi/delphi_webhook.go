// pkg/delphi/delphi_webhook.go

package delphi

import (
	"context"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cmd_helpers"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployDelphiWebhook deploys Delphi webhook scripts to target directory
func DeployDelphiWebhook(ctx context.Context, logger otelzap.LoggerWithCtx, targetDir string, dryRun, force bool) error {
	// Create file service container
	rc := &eos_io.RuntimeContext{Ctx: ctx, Log: logger.Logger().Logger}
	fileContainer, err := cmd_helpers.NewFileServiceContainer(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize file operations: %w", err)
	}

	// Define script paths
	pythonScript := "/usr/local/share/eos/assets/delphi_webhook.py"
	bashScript := "/usr/local/share/eos/assets/delphi_webhook.sh"
	pythonDest := targetDir + "/delphi_webhook.py"
	bashDest := targetDir + "/delphi_webhook.sh"

	// Check if source files exist
	for _, src := range []string{pythonScript, bashScript} {
		if !fileContainer.FileExists(src) {
			return fmt.Errorf("source file not found: %s", src)
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
	// Note: We need a custom copy for 0750 permissions
	copyWithPermissions := func(src, dst string, perm os.FileMode) error {
		data, err := fileContainer.Service.ReadFile(ctx, src)
		if err != nil {
			return err
		}
		return fileContainer.Service.WriteFile(ctx, dst, data, perm)
	}

	// OLD: if err := copyFile(pythonScript, pythonDest); err != nil {
	// NEW:
	if err := copyWithPermissions(pythonScript, pythonDest, 0750); err != nil {
		return fmt.Errorf("failed to copy Python script: %w", err)
	}

	// OLD: if err := copyFile(bashScript, bashDest); err != nil {
	// NEW:
	if err := copyWithPermissions(bashScript, bashDest, 0750); err != nil {
		return fmt.Errorf("failed to copy bash script: %w", err)
	}

	if !dryRun {
		logger.Info("Delphi webhook scripts deployed successfully",
			zap.String("target_dir", targetDir))
		printPostDeploymentInstructions(logger)
	} else {
		logger.Info("Dry run completed - no files were actually copied")
	}

	return nil
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
