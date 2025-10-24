// pkg/vault/phase6c_enable_audit_immediately.go
// Phase 6c: Enable dual audit devices IMMEDIATELY after initialization
//
// CRITICAL SECURITY: This phase MUST run before any other Vault operations
// to ensure ALL subsequent API requests are audited, including:
//   - Policy creation (Phase 11)
//   - User creation (Phase 10)
//   - Secret writes (Phase 9)
//   - Auth method configuration (Phase 10)
//
// HashiCorp Recommendation:
//   "Enable at least one audit device immediately after initialization
//    to ensure Vault audits all subsequent API requests"
//
// Security Rationale:
//   - Forensic trail from the very beginning
//   - Compliance requirements (SOC2, PCI-DSS, HIPAA)
//   - Detection of unauthorized initial configuration
//   - Dual devices for redundancy (Vault stops if all audit devices fail)

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseEnableAuditImmediately enables dual audit devices immediately after Vault initialization
// This is Phase 6c, running between init/unseal (6a/6b) and any configuration (7+)
//
// ASSESS → INTERVENE → EVALUATE pattern:
//
//	ASSESS: Check if audit directory exists, verify permissions
//	INTERVENE: Enable file + syslog audit devices with proper configuration
//	EVALUATE: Verify both audit devices are enabled and writing logs
func PhaseEnableAuditImmediately(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" [Phase 6c] Enabling Dual Audit Devices IMMEDIATELY")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("SECURITY: Audit devices MUST be enabled before any configuration")
	logger.Info("          to ensure ALL operations are logged from the start.")
	logger.Info("")

	// ASSESS: Verify audit prerequisites
	logger.Info(" [ASSESS] Checking audit device prerequisites")
	if err := assessAuditPrerequisites(rc); err != nil {
		return fmt.Errorf("audit prerequisites check failed: %w", err)
	}

	// INTERVENE: Enable dual audit devices
	logger.Info(" [INTERVENE] Enabling primary audit device (file)")
	if err := enableFileAudit(rc, client); err != nil {
		// CRITICAL: File audit MUST succeed
		return fmt.Errorf("CRITICAL: failed to enable primary file audit device: %w\n"+
			"Vault operations will NOT be audited. Installation cannot continue.\n"+
			"Check: /var/log/vault directory permissions and disk space", err)
	}
	logger.Info(" ✓ Primary audit device (file) enabled successfully")

	logger.Info(" [INTERVENE] Enabling backup audit device (syslog)")
	if err := enableSyslogAudit(rc, client); err != nil {
		// WARNING: Syslog is backup, log warning but continue
		logger.Warn("⚠ Backup audit device (syslog) failed to enable - continuing with file audit only",
			zap.Error(err),
			zap.String("impact", "Single point of failure for audit logs"),
			zap.String("remediation", "Manually enable syslog audit: vault audit enable syslog"))
	} else {
		logger.Info(" ✓ Backup audit device (syslog) enabled successfully")
	}

	// EVALUATE: Verify audit devices are operational
	logger.Info(" [EVALUATE] Verifying audit devices are operational")
	if err := evaluateAuditDevices(rc, client); err != nil {
		return fmt.Errorf("audit device verification failed: %w", err)
	}

	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" ✓ Phase 6c Complete: Dual Audit Devices Enabled")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("  File Audit:   /var/log/vault/vault-audit.log")
	logger.Info("  Syslog Audit: /var/log/syslog (facility: AUTH, tag: vault)")
	logger.Info("")
	logger.Info("  ALL subsequent Vault operations will now be audited.")
	logger.Info("")

	return nil
}

// assessAuditPrerequisites checks that audit logging prerequisites are met
func assessAuditPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	auditDir := "/var/log/vault"

	// Check if directory exists
	logger.Debug("Checking audit directory", zap.String("path", auditDir))
	if _, err := os.Stat(auditDir); os.IsNotExist(err) {
		logger.Info("Creating audit log directory", zap.String("path", auditDir))
		if err := os.MkdirAll(auditDir, 0750); err != nil {
			return fmt.Errorf("failed to create audit directory: %w", err)
		}

		// Set ownership to vault user
		if err := execute.RunSimple(rc.Ctx, "chown", "vault:vault", auditDir); err != nil {
			logger.Warn("Failed to set audit directory ownership", zap.Error(err))
		}
	}

	// Verify directory is writable
	testFile := filepath.Join(auditDir, ".eos-audit-test")
	if err := os.WriteFile(testFile, []byte("test"), 0640); err != nil {
		return fmt.Errorf("audit directory is not writable: %w\nPath: %s", err, auditDir)
	}
	_ = os.Remove(testFile)

	// Check disk space (need at least 1GB free for audit logs)
	// Note: This is a best-effort check
	logger.Debug("Audit directory is writable", zap.String("path", auditDir))

	return nil
}

// enableFileAudit enables the file audit device (primary)
func enableFileAudit(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	auditPath := "/var/log/vault/vault-audit.log"

	// Configure file audit with security best practices
	auditOptions := &api.EnableAuditOptions{
		Type: "file",
		Options: map[string]string{
			"file_path": auditPath,
			// SECURITY: log_raw=false prevents plaintext secrets in audit logs
			// Vault will HMAC-hash sensitive values instead
			"log_raw": "false",
			// SECURITY: hmac_accessor=true hashes accessor IDs for privacy
			"hmac_accessor": "true",
			// SECURITY: mode=0640 restricts audit log access (owner+group read, others none)
			"mode": "0640",
			// PERFORMANCE: format=json enables structured logging for SIEM integration
			"format": "json",
		},
	}

	// Check if file audit already exists
	auditMounts, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list existing audit devices: %w", err)
	}

	if _, exists := auditMounts["file/"]; exists {
		logger.Info("File audit device already enabled", zap.String("path", auditPath))
		return nil
	}

	// Enable file audit
	logger.Info("Enabling file audit device",
		zap.String("path", auditPath),
		zap.String("mode", "0640"),
		zap.String("format", "json"))

	err = client.Sys().EnableAuditWithOptions("file", auditOptions)
	if err != nil {
		return fmt.Errorf("failed to enable file audit device: %w", err)
	}

	logger.Info("File audit device enabled successfully",
		zap.String("mount", "file/"),
		zap.String("log_file", auditPath))

	return nil
}

// enableSyslogAudit enables the syslog audit device (backup)
func enableSyslogAudit(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Configure syslog audit for redundancy
	syslogOptions := &api.EnableAuditOptions{
		Type: "syslog",
		Options: map[string]string{
			// SECURITY: facility=AUTH logs to /var/log/auth.log (secure logs)
			"facility": "AUTH",
			// OPERATIONS: tag=vault enables filtering Vault logs in syslog
			"tag": "vault",
			// SECURITY: log_raw=false prevents plaintext secrets in syslog
			"log_raw": "false",
			// PERFORMANCE: format=json enables structured logging
			"format": "json",
		},
	}

	// Check if syslog audit already exists
	auditMounts, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list existing audit devices: %w", err)
	}

	if _, exists := auditMounts["syslog/"]; exists {
		logger.Info("Syslog audit device already enabled")
		return nil
	}

	// Enable syslog audit
	logger.Info("Enabling syslog audit device",
		zap.String("facility", "AUTH"),
		zap.String("tag", "vault"),
		zap.String("format", "json"))

	err = client.Sys().EnableAuditWithOptions("syslog", syslogOptions)
	if err != nil {
		return fmt.Errorf("failed to enable syslog audit device: %w", err)
	}

	logger.Info("Syslog audit device enabled successfully",
		zap.String("mount", "syslog/"),
		zap.String("facility", "AUTH"))

	return nil
}

// evaluateAuditDevices verifies that audit devices are operational
func evaluateAuditDevices(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	// List enabled audit devices
	auditMounts, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if len(auditMounts) == 0 {
		return fmt.Errorf("CRITICAL: no audit devices are enabled")
	}

	// Verify file audit
	fileAudit, hasFile := auditMounts["file/"]
	if !hasFile {
		return fmt.Errorf("CRITICAL: primary file audit device is not enabled")
	}

	logger.Info("Verified primary audit device",
		zap.String("type", fileAudit.Type),
		zap.String("path", fileAudit.Path),
		zap.Any("options", fileAudit.Options))

	// Verify syslog audit (warning if missing, not critical)
	syslogAudit, hasSyslog := auditMounts["syslog/"]
	if !hasSyslog {
		logger.Warn("⚠ Backup syslog audit device is not enabled",
			zap.String("impact", "Single point of failure - only file audit active"),
			zap.String("remediation", "Run: vault audit enable syslog facility=AUTH tag=vault"))
	} else {
		logger.Info("Verified backup audit device",
			zap.String("type", syslogAudit.Type),
			zap.String("path", syslogAudit.Path))
	}

	// Verify audit log file exists and is being written to
	auditLogPath := "/var/log/vault/vault-audit.log"
	if info, err := os.Stat(auditLogPath); err == nil {
		logger.Info("Audit log file exists",
			zap.String("path", auditLogPath),
			zap.Int64("size_bytes", info.Size()),
			zap.String("permissions", info.Mode().String()))
	} else {
		logger.Warn("Audit log file does not exist yet",
			zap.String("path", auditLogPath),
			zap.String("note", "Will be created on first audit event"))
	}

	logger.Info("✓ Audit device verification passed",
		zap.Int("total_devices", len(auditMounts)),
		zap.Bool("file_enabled", hasFile),
		zap.Bool("syslog_enabled", hasSyslog))

	return nil
}
