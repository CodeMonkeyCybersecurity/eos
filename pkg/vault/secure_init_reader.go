// pkg/vault/secure_init_reader.go

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultInitInfo represents comprehensive Vault initialization information
type VaultInitInfo struct {
	InitResponse   *api.InitResponse     `json:"init_response"`
	FileInfo       *VaultInitFileInfo    `json:"file_info"`
	VaultStatus    *VaultStatusInfo      `json:"vault_status"`
	SecurityStatus *SecurityStatusInfo   `json:"security_status"`
	EosCredentials *shared.UserpassCreds `json:"eos_credentials,omitempty"`
	AccessAudit    *AccessAuditInfo      `json:"access_audit"`
}

type VaultInitFileInfo struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"modification_time"`
	Checksum    string    `json:"checksum"`
	Permissions string    `json:"permissions"`
	Owner       string    `json:"owner"`
	Exists      bool      `json:"exists"`
	Readable    bool      `json:"readable"`
}

type VaultStatusInfo struct {
	Running      bool   `json:"running"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	Address      string `json:"address"`
	Version      string `json:"version,omitempty"`
	Reachable    bool   `json:"reachable"`
	HealthStatus string `json:"health_status"`
}

type SecurityStatusInfo struct {
	MFAEnabled         bool     `json:"mfa_enabled"`
	AuditEnabled       bool     `json:"audit_enabled"`
	AuthMethods        []string `json:"auth_methods"`
	HardeningApplied   bool     `json:"hardening_applied"`
	RootTokenRevoked   bool     `json:"root_token_revoked"`
	BackupConfigured   bool     `json:"backup_configured"`
	FirewallConfigured bool     `json:"firewall_configured"`
}

type AccessAuditInfo struct {
	AccessedBy    string    `json:"accessed_by"`
	AccessTime    time.Time `json:"access_time"`
	AccessReason  string    `json:"access_reason"`
	RedactionMode string    `json:"redaction_mode"`
}

// ReadInitOptions controls how vault init data is read and displayed
type ReadInitOptions struct {
	RedactSensitive bool   `json:"redact_sensitive"`
	VerifyIntegrity bool   `json:"verify_integrity"`
	IncludeStatus   bool   `json:"include_status"`
	AuditAccess     bool   `json:"audit_access"`
	ExportFormat    string `json:"export_format"` // "console", "json", "secure"
	OutputPath      string `json:"output_path,omitempty"`
	RequireConfirm  bool   `json:"require_confirmation"`
	AccessReason    string `json:"access_reason,omitempty"`
}

// DefaultReadInitOptions returns secure defaults for reading vault init data
func DefaultReadInitOptions() *ReadInitOptions {
	return &ReadInitOptions{
		RedactSensitive: true,
		VerifyIntegrity: true,
		IncludeStatus:   true,
		AuditAccess:     true,
		ExportFormat:    "console",
		RequireConfirm:  true,
	}
}

// SecureReadVaultInit provides secure, comprehensive reading of Vault initialization data
func SecureReadVaultInit(rc *eos_io.RuntimeContext, options *ReadInitOptions) (*VaultInitInfo, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting secure Vault init data access")

	if options == nil {
		options = DefaultReadInitOptions()
	}

	// Create comprehensive vault init info
	info := &VaultInitInfo{
		AccessAudit: &AccessAuditInfo{
			AccessTime:    time.Now().UTC(),
			AccessReason:  options.AccessReason,
			RedactionMode: getRedactionMode(options.RedactSensitive),
		},
	}

	// Get current user for audit
	if currentUser, err := user.Current(); err == nil {
		info.AccessAudit.AccessedBy = currentUser.Username
	}

	// Perform security verification
	if err := performSecurityVerification(rc, options); err != nil {
		return nil, fmt.Errorf("security verification failed: %w", err)
	}

	// Read and verify vault init file
	initResponse, fileInfo, err := readAndVerifyInitFile(rc, options)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault init file: %w", err)
	}
	info.InitResponse = initResponse
	info.FileInfo = fileInfo

	// Get current Vault status if requested
	if options.IncludeStatus {
		vaultStatus, err := getVaultStatus(rc)
		if err != nil {
			log.Warn("Failed to get Vault status", zap.Error(err))
			vaultStatus = &VaultStatusInfo{Running: false, Reachable: false}
		}
		info.VaultStatus = vaultStatus

		// Get security status
		securityStatus, err := getSecurityStatus(rc)
		if err != nil {
			log.Warn("Failed to get security status", zap.Error(err))
		}
		info.SecurityStatus = securityStatus
	}

	// Load Eos credentials if available
	if eosCreds, err := eos_unix.LoadPasswordFromSecrets(rc.Ctx); err == nil {
		info.EosCredentials = eosCreds
	}

	// Audit the access
	if options.AuditAccess {
		auditVaultInitAccess(rc, info.AccessAudit)
	}

	log.Info(" Secure Vault init data access completed")
	return info, nil
}

// performSecurityVerification checks if the user should have access to vault init data
func performSecurityVerification(rc *eos_io.RuntimeContext, options *ReadInitOptions) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if running as root or eos user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Verify user permissions
	if currentUser.Uid != "0" && currentUser.Username != "eos" {
		return fmt.Errorf("vault init data access requires root or eos user privileges")
	}

	// Require confirmation for sensitive data access
	if options.RequireConfirm && !options.RedactSensitive {
		log.Warn(" SECURITY WARNING: Requesting access to sensitive Vault initialization data")
		log.Info("terminal prompt: SECURITY WARNING")
		log.Info("terminal prompt: You are requesting access to highly sensitive Vault initialization data including:")
		log.Info("terminal prompt:    • Root token (full Vault administrative access)")
		log.Info("terminal prompt:    • Unseal keys (ability to unseal Vault)")
		log.Info("terminal prompt:    • Eos user credentials")

		reason := options.AccessReason
		if reason == "" {
			reasonInput, err := interaction.PromptSecrets(rc.Ctx, "Access reason (required for audit)", 1)
			if err != nil {
				return fmt.Errorf("access reason required: %w", err)
			}
			reason = reasonInput[0]
			options.AccessReason = reason
		}

		if !interaction.PromptYesNo(rc.Ctx, "Continue with sensitive data access?", false) {
			return fmt.Errorf("vault init access cancelled by user")
		}
	}

	log.Info(" Security verification passed",
		zap.String("user", currentUser.Username),
		zap.String("access_reason", options.AccessReason))
	return nil
}

// readAndVerifyInitFile reads the vault init file with integrity verification
func readAndVerifyInitFile(rc *eos_io.RuntimeContext, options *ReadInitOptions) (*api.InitResponse, *VaultInitFileInfo, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Get file info
	fileInfo, err := getInitFileInfo(shared.VaultInitPath)
	if err != nil {
		return nil, fileInfo, fmt.Errorf("failed to get vault init file info: %w", err)
	}

	if !fileInfo.Exists {
		return nil, fileInfo, fmt.Errorf("vault init file not found at %s", shared.VaultInitPath)
	}

	if !fileInfo.Readable {
		return nil, fileInfo, fmt.Errorf("vault init file not readable")
	}

	// Read and parse the file
	data, err := os.ReadFile(shared.VaultInitPath)
	if err != nil {
		return nil, fileInfo, fmt.Errorf("failed to read vault init file: %w", err)
	}

	var initResponse api.InitResponse
	if err := json.Unmarshal(data, &initResponse); err != nil {
		return nil, fileInfo, fmt.Errorf("failed to parse vault init file: %w", err)
	}

	// Verify integrity if requested
	if options.VerifyIntegrity {
		if err := verifyInitDataIntegrity(&initResponse); err != nil {
			log.Warn("Vault init data integrity check failed", zap.Error(err))
		} else {
			log.Info(" Vault init data integrity verified")
		}
	}

	return &initResponse, fileInfo, nil
}

// getInitFileInfo gathers comprehensive information about the vault init file
func getInitFileInfo(path string) (*VaultInitFileInfo, error) {
	info := &VaultInitFileInfo{
		Path: path,
	}

	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			info.Exists = false
			return info, nil
		}
		return info, err
	}

	info.Exists = true
	info.Size = stat.Size()
	info.ModTime = stat.ModTime()
	info.Permissions = stat.Mode().String()

	// Check if readable
	if _, err := os.ReadFile(path); err == nil {
		info.Readable = true

		// Calculate checksum
		data, _ := os.ReadFile(path)
		hash := sha256.Sum256(data)
		info.Checksum = hex.EncodeToString(hash[:])
	}

	// Get owner information
	if stat.Sys() != nil {
		info.Owner = "system" // Simplified for cross-platform compatibility
	}

	return info, nil
}

// verifyInitDataIntegrity performs basic validation of vault init data
func verifyInitDataIntegrity(initResponse *api.InitResponse) error {
	if initResponse.RootToken == "" {
		return fmt.Errorf("root token is empty")
	}

	if len(initResponse.KeysB64) == 0 {
		return fmt.Errorf("no unseal keys found")
	}

	// Verify token format (basic validation)
	if !strings.HasPrefix(initResponse.RootToken, "hvs.") &&
		!strings.HasPrefix(initResponse.RootToken, "s.") &&
		len(initResponse.RootToken) < 20 {
		return fmt.Errorf("root token format appears invalid")
	}

	// Verify unseal keys format
	for i, key := range initResponse.KeysB64 {
		if len(key) < 20 {
			return fmt.Errorf("unseal key %d appears invalid (too short)", i+1)
		}
	}

	return nil
}

// getVaultStatus retrieves current Vault operational status
func getVaultStatus(rc *eos_io.RuntimeContext) (*VaultStatusInfo, error) {
	log := otelzap.Ctx(rc.Ctx)

	status := &VaultStatusInfo{
		Address: shared.GetVaultAddr(),
	}

	// Check if Vault is running and reachable
	client, err := GetVaultClient(rc)
	if err != nil {
		log.Debug("Vault client not available", zap.Error(err))
		return status, nil
	}

	status.Reachable = true

	// Get health status
	health, err := client.Sys().Health()
	if err != nil {
		log.Debug("Vault health check failed", zap.Error(err))
		status.HealthStatus = "unhealthy"
		return status, nil
	}

	status.Running = true
	status.Initialized = health.Initialized
	status.Sealed = health.Sealed
	status.Version = health.Version

	if health.Initialized && !health.Sealed {
		status.HealthStatus = "healthy"
	} else if health.Sealed {
		status.HealthStatus = "sealed"
	} else {
		status.HealthStatus = "uninitialized"
	}

	return status, nil
}

// getSecurityStatus checks current security configuration
func getSecurityStatus(rc *eos_io.RuntimeContext) (*SecurityStatusInfo, error) {
	status := &SecurityStatusInfo{}

	// Try to get a client to check security status
	client, err := GetVaultClient(rc)
	if err != nil {
		return status, nil
	}

	// Check if Vault is accessible
	if IsVaultSealed(client) {
		return status, nil
	}

	// Check auth methods
	authMethods, err := client.Sys().ListAuth()
	if err == nil {
		for path, method := range authMethods {
			status.AuthMethods = append(status.AuthMethods, fmt.Sprintf("%s (%s)", path, method.Type))
		}
	}

	// Check for MFA (simplified check)
	status.MFAEnabled = len(status.AuthMethods) > 1 // Basic heuristic

	// Check audit devices
	auditDevices, err := client.Sys().ListAudit()
	if err == nil {
		status.AuditEnabled = len(auditDevices) > 0
	}

	// Check for hardening indicators
	status.HardeningApplied = checkHardeningStatus()
	status.BackupConfigured = checkBackupStatus()
	status.FirewallConfigured = checkFirewallStatus()

	return status, nil
}

// Helper functions for security status checks
func checkHardeningStatus() bool {
	// Check if hardening script exists
	_, err := os.Stat("/usr/local/bin/vault-backup.sh")
	return err == nil
}

func checkBackupStatus() bool {
	// Check if backup directory exists
	_, err := os.Stat("/var/backups/vault")
	return err == nil
}

func checkFirewallStatus() bool {
	// Basic check for UFW or firewalld
	_, ufwErr := os.Stat("/usr/sbin/ufw")
	_, firewalldErr := os.Stat("/usr/bin/firewall-cmd")
	return ufwErr == nil || firewalldErr == nil
}

// auditVaultInitAccess logs the access to vault init data for security audit
func auditVaultInitAccess(rc *eos_io.RuntimeContext, audit *AccessAuditInfo) {
	log := otelzap.Ctx(rc.Ctx)

	// Log to structured logs
	log.Warn(" AUDIT: Vault initialization data accessed",
		zap.String("accessed_by", audit.AccessedBy),
		zap.Time("access_time", audit.AccessTime),
		zap.String("access_reason", audit.AccessReason),
		zap.String("redaction_mode", audit.RedactionMode))

	// Write to audit file
	auditDir := "/var/log/eos"
	auditFile := filepath.Join(auditDir, "vault-access.log")

	if err := os.MkdirAll(auditDir, 0750); err == nil {
		auditEntry := fmt.Sprintf("[%s] User '%s' accessed vault init data. Reason: '%s', Redaction: %s\n",
			audit.AccessTime.Format(time.RFC3339),
			audit.AccessedBy,
			audit.AccessReason,
			audit.RedactionMode)

		f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err == nil {
			if _, err := f.WriteString(auditEntry); err != nil {
				// Log silently as this is audit logging and shouldn't fail the main operation
				_ = err
			}
			if err := f.Close(); err != nil {
				// Log silently as well
				_ = err
			}
		}
	}
}

// getRedactionMode returns a string describing the redaction mode
func getRedactionMode(redacted bool) string {
	if redacted {
		return "redacted"
	}
	return "plaintext"
}

// DisplayVaultInitInfo presents the vault init information in a user-friendly format
func DisplayVaultInitInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo, options *ReadInitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Vault Initialization Information")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Display file information
	if info.FileInfo != nil {
		logger.Info("Init File Information")
		logger.Info("File details",
			zap.String("path", info.FileInfo.Path),
			zap.Int64("size_bytes", info.FileInfo.Size),
			zap.String("modified", info.FileInfo.ModTime.Format(time.RFC3339)),
			zap.String("checksum_preview", info.FileInfo.Checksum[:16]+"..."),
			zap.String("permissions", info.FileInfo.Permissions))
	}

	// Display Vault status
	if info.VaultStatus != nil {
		logger.Info("🏛️ Vault Status")
		logger.Info("Vault service status",
			zap.String("address", info.VaultStatus.Address),
			zap.Bool("running", info.VaultStatus.Running),
			zap.Bool("initialized", info.VaultStatus.Initialized),
			zap.Bool("sealed", info.VaultStatus.Sealed),
			zap.String("health", info.VaultStatus.HealthStatus),
			zap.String("version", info.VaultStatus.Version))
	}

	// Display security status
	if info.SecurityStatus != nil {
		logger.Info("Security Status")
		logger.Info("Security configuration",
			zap.Bool("mfa_enabled", info.SecurityStatus.MFAEnabled),
			zap.Bool("audit_enabled", info.SecurityStatus.AuditEnabled),
			zap.Bool("hardening_applied", info.SecurityStatus.HardeningApplied),
			zap.Int("auth_methods_count", len(info.SecurityStatus.AuthMethods)),
			zap.Strings("auth_methods", info.SecurityStatus.AuthMethods))
	}

	// Display initialization data
	if info.InitResponse != nil {
		logger.Info("Vault Initialization Data")

		if options.RedactSensitive {
			logger.Info("Vault initialization credentials (redacted)",
				zap.String("root_token", crypto.Redact(info.InitResponse.RootToken)),
				zap.Int("unseal_keys_count", len(info.InitResponse.KeysB64)))
			
			for i, key := range info.InitResponse.KeysB64 {
				logger.Info("Unseal key (redacted)",
					zap.Int("key_number", i+1),
					zap.String("key_value", crypto.Redact(key)))
			}
			logger.Info("terminal prompt: Sensitive data is redacted. Use --no-redact flag to show plaintext.")
		} else {
			// SECURITY: Log plaintext credentials with high security audit level
			logger.Error("SECURITY AUDIT: Displaying plaintext Vault credentials",
				zap.String("event_type", "sensitive_data_display"),
				zap.String("data_type", "vault_init_credentials"))
			
			logger.Info("Vault initialization credentials (PLAINTEXT)",
				zap.String("root_token", info.InitResponse.RootToken),
				zap.Int("unseal_keys_count", len(info.InitResponse.KeysB64)))
			
			for i, key := range info.InitResponse.KeysB64 {
				logger.Info("Unseal key (PLAINTEXT)",
					zap.Int("key_number", i+1),
					zap.String("key_value", key))
			}
		}
	}

	// Display Eos credentials
	if info.EosCredentials != nil {
		logger.Info("Eos User Credentials")
		
		if options.RedactSensitive {
			logger.Info("Eos credentials (redacted)",
				zap.String("username", info.EosCredentials.Username),
				zap.String("password", crypto.Redact(info.EosCredentials.Password)))
		} else {
			// SECURITY: Log plaintext credentials with high security audit level
			logger.Error("SECURITY AUDIT: Displaying plaintext Eos credentials",
				zap.String("event_type", "sensitive_data_display"),
				zap.String("data_type", "eos_user_credentials"))
			
			logger.Info("Eos credentials (PLAINTEXT)",
				zap.String("username", info.EosCredentials.Username),
				zap.String("password", info.EosCredentials.Password))
		}
	}

	// Display next steps
	displayNextSteps(rc, info)

	// Display security reminders
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Security Reminders")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Security best practices",
		zap.Strings("reminders", []string{
			"Store this information securely (password manager, encrypted storage)",
			"Never share root tokens or unseal keys via insecure channels",
			"Consider revoking root token after setting up alternative auth",
			"Ensure Vault is properly hardened before production use",
		}))

	return nil
}

// displayNextSteps provides contextual guidance based on Vault status
func displayNextSteps(rc *eos_io.RuntimeContext, info *VaultInitInfo) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Recommended Next Steps")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if info.VaultStatus == nil {
		logger.Info("Next step: Check Vault installation and configuration")
		return
	}

	var nextSteps []string
	
	if !info.VaultStatus.Running {
		nextSteps = append(nextSteps, "Start Vault service: systemctl start vault")
	} else if info.VaultStatus.Sealed {
		nextSteps = append(nextSteps, "Unseal Vault: eos enable vault")
	} else if !info.SecurityStatus.MFAEnabled {
		nextSteps = append(nextSteps, "Configure MFA: Run enable vault workflow")
	} else if !info.SecurityStatus.HardeningApplied {
		nextSteps = append(nextSteps, "Apply security hardening: eos secure vault --comprehensive")
	} else {
		nextSteps = append(nextSteps, 
			"Vault appears to be properly configured",
			"Consider backing up this initialization data securely",
			"Review audit logs regularly")
	}
	
	logger.Info("Recommended actions", zap.Strings("next_steps", nextSteps))
}
