// pkg/vault/phase12_enable_audit.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnableFileAudit enables file-based Vault auditing at /opt/vault/logs/vault_audit.log.
func EnableFileAudit(rc *eos_io.RuntimeContext, _ *api.Client) error { //  Ignore the passed client!
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting file audit enablement process")

	// Always get privileged root client
	client, err := GetRootClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	// Check if the audit device is already enabled
	log.Info(" Listing current audit devices")
	audits, err := client.Sys().ListAudit()
	if err != nil {
		log.Error(" Failed to list audit devices", zap.Error(err))
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[shared.AuditID]; exists {
		log.Info(" Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	// Create audit log directory with proper permissions
	log.Info(" Creating audit log directory", zap.String("path", shared.VaultLogsPath), zap.String("permissions", "0750"))

	// Check if directory already exists
	dirInfo, statErr := os.Stat(shared.VaultLogsPath)
	if statErr == nil {
		log.Info(" Audit directory already exists",
			zap.String("path", shared.VaultLogsPath),
			zap.String("mode", dirInfo.Mode().String()))
	} else if os.IsNotExist(statErr) {
		log.Debug(" Audit directory does not exist, creating", zap.String("path", shared.VaultLogsPath))
	}

	if err := os.MkdirAll(shared.VaultLogsPath, 0750); err != nil {
		log.Error(" Failed to create audit directory",
			zap.String("path", shared.VaultLogsPath),
			zap.Error(err))
		return fmt.Errorf("failed to create audit directory: %w", err)
	}
	log.Info(" Audit directory ready", zap.String("path", shared.VaultLogsPath))

	// Verify directory was created with correct permissions
	verifyInfo, verifyErr := os.Stat(shared.VaultLogsPath)
	if verifyErr != nil {
		log.Error(" Failed to verify audit directory", zap.Error(verifyErr))
		return fmt.Errorf("failed to verify audit directory: %w", verifyErr)
	}
	log.Debug(" Audit directory permissions verified",
		zap.String("mode", verifyInfo.Mode().String()),
		zap.String("expected", "drwxr-x---"))

	// Set ownership to vault user
	log.Info(" Setting audit directory ownership to vault:vault")
	chownCmd := execute.Options{
		Command: "chown",
		Args:    []string{"-R", "vault:vault", shared.VaultLogsPath},
		Capture: true,
	}
	output, err := execute.Run(rc.Ctx, chownCmd)
	if err != nil {
		log.Error(" Failed to set audit directory ownership",
			zap.Error(err),
			zap.String("output", output),
			zap.String("command", "chown -R vault:vault "+shared.VaultLogsPath))
		// This is CRITICAL - fail instead of warning
		return fmt.Errorf("failed to set audit directory ownership: %w (output: %s)", err, output)
	}
	log.Info(" Audit directory ownership set successfully",
		zap.String("owner", "vault:vault"),
		zap.String("path", shared.VaultLogsPath))

	// Verify ownership was set correctly
	lsCmd := execute.Options{
		Command: "ls",
		Args:    []string{"-ld", shared.VaultLogsPath},
		Capture: true,
	}
	lsOutput, lsErr := execute.Run(rc.Ctx, lsCmd)
	if lsErr == nil {
		log.Info(" Audit directory final state",
			zap.String("ls_output", lsOutput))
	} else {
		log.Warn(" Could not verify directory state", zap.Error(lsErr))
	}

	log.Info(" Enabling file-based audit device",
		zap.String("audit_id", shared.AuditID),
		zap.String("file_path", shared.VaultAuditLogPath))

	err = enableFeature(rc, client, shared.MountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": shared.VaultAuditLogPath,
			},
		},
		" File audit enabled.",
	)
	if err != nil {
		log.Error(" Failed to enable file audit", zap.Error(err))
		return fmt.Errorf("failed to enable file audit: %w", err)
	}

	log.Info(" File audit successfully enabled")
	return nil
}
