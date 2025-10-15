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
func EnableFileAudit(rc *eos_io.RuntimeContext, _ *api.Client) error { // 🔥 Ignore the passed client!
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
	log.Info(" Creating audit log directory", zap.String("path", shared.VaultLogsPath))
	if err := os.MkdirAll(shared.VaultLogsPath, 0750); err != nil {
		log.Error(" Failed to create audit directory", zap.Error(err))
		return fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Set ownership to vault user
	log.Info(" Setting audit directory ownership to vault:vault")
	if err := execute.RunSimple(rc.Ctx, "chown", "-R", "vault:vault", shared.VaultLogsPath); err != nil {
		log.Warn(" Failed to set audit directory ownership", zap.Error(err))
		// Don't fail - Vault might still work with root ownership
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
