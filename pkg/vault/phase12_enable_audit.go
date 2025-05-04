// pkg/vault/phase12_enable_audit.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnableFileAudit enables file-based Vault auditing at /opt/vault/logs/vault_audit.log.
func EnableFileAudit(existingClient *api.Client) error {
	log := zap.L().Named("EnableFileAudit")
	log.Info("🔐 Starting file audit enablement process")

	var client *api.Client
	var err error

	// Check if an external client was passed in; if nil, get a root client
	if existingClient == nil {
		log.Info("🔑 No client provided; retrieving privileged root client")
		client, err = GetRootClient()
		if err != nil {
			log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
			return fmt.Errorf("get privileged vault client: %w", err)
		}
	} else {
		client = existingClient
		log.Info("✅ Using provided Vault client")
	}

	// Check if the audit device is already enabled
	log.Info("🔍 Listing current audit devices")
	audits, err := client.Sys().ListAudit()
	if err != nil {
		log.Error("❌ Failed to list audit devices", zap.Error(err))
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[shared.AuditID]; exists {
		log.Info("✅ Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	log.Info("➕ Enabling file-based audit device",
		zap.String("audit_id", shared.AuditID),
		zap.String("file_path", "/opt/vault/logs/vault_audit.log"))

	// Enable the audit device at the correct location
	err = enableFeature(client, shared.MountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/opt/vault/logs/vault_audit.log",
			},
		},
		"✅ File audit enabled.",
	)
	if err != nil {
		log.Error("❌ Failed to enable file audit", zap.Error(err))
		return fmt.Errorf("failed to enable file audit: %w", err)
	}

	log.Info("🎉 File audit successfully enabled")
	return nil
}
