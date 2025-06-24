// pkg/vault/phase12_enable_audit.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
	log.Info("🔍 Listing current audit devices")
	audits, err := client.Sys().ListAudit()
	if err != nil {
		log.Error(" Failed to list audit devices", zap.Error(err))
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[shared.AuditID]; exists {
		log.Info(" Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	log.Info(" Enabling file-based audit device",
		zap.String("audit_id", shared.AuditID),
		zap.String("file_path", "/opt/vault/logs/vault_audit.log"))

	err = enableFeature(client, shared.MountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/opt/vault/logs/vault_audit.log",
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
