package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// SaltVerify performs comprehensive verification of Vault installation and configuration
func SaltVerify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault verification")
	
	// Load default config for verification
	config := DefaultSaltConfig()
	
	// ASSESS - Check what needs to be verified
	logger.Info("Assessing Vault installation status")
	status, err := assessVaultStatus(rc, config)
	if err != nil {
		return fmt.Errorf("failed to assess vault status: %w", err)
	}
	
	// INTERVENE - Perform verification checks
	logger.Info("Performing verification checks")
	results, err := performVerificationChecks(rc, config, status)
	if err != nil {
		return fmt.Errorf("verification checks failed: %w", err)
	}
	
	// EVALUATE - Analyze results
	logger.Info("Evaluating verification results")
	if err := evaluateResults(rc, results); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	
	// Display summary
	displayVerificationSummary(rc, results)
	
	logger.Info("Vault verification completed successfully")
	return nil
}

// VaultVerificationStatus holds the current status of Vault
type VaultVerificationStatus struct {
	Installed      bool
	Version        string
	ServiceActive  bool
	Initialized    bool
	Sealed         bool
	TLSEnabled     bool
	AuditEnabled   bool
	AuthMethods    []string
	Policies       []string
	ClusterID      string
}

// VerificationResults holds the results of all verification checks
type VerificationResults struct {
	Status           *VaultVerificationStatus
	BinaryCheck      bool
	ServiceCheck     bool
	ConfigCheck      bool
	TLSCheck         bool
	NetworkCheck     bool
	StorageCheck     bool
	PermissionsCheck bool
	AuditCheck       bool
	BackupCheck      bool
	Issues           []string
	Warnings         []string
}

func assessVaultStatus(rc *eos_io.RuntimeContext, config *SaltConfig) (*VaultVerificationStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &VaultVerificationStatus{}
	
	// Check if Vault is installed
	cmd := exec.CommandContext(rc.Ctx, "vault", "version")
	if output, err := cmd.Output(); err == nil {
		status.Installed = true
		status.Version = strings.TrimSpace(string(output))
		logger.Info("Vault binary found", zap.String("version", status.Version))
	} else {
		logger.Warn("Vault binary not found")
		return status, nil
	}
	
	// Check service status
	cmd = exec.CommandContext(rc.Ctx, "systemctl", "is-active", VaultServiceName)
	if output, err := cmd.Output(); err == nil {
		status.ServiceActive = strings.TrimSpace(string(output)) == "active"
	}
	
	// Check Vault status
	cmd = exec.CommandContext(rc.Ctx, "vault", "status", "-format=json")
	statusOutput, err := cmd.Output()
	if err != nil && !strings.Contains(err.Error(), "exit status 2") {
		logger.Warn("Failed to get vault status", zap.Error(err))
		return status, nil
	}
	
	var vaultStatus VaultStatus
	if err := json.Unmarshal(statusOutput, &vaultStatus); err == nil {
		status.Initialized = vaultStatus.Initialized
		status.Sealed = vaultStatus.Sealed
		status.ClusterID = vaultStatus.ClusterID
	}
	
	// Check TLS configuration
	vaultAddr := os.Getenv(VaultAddrEnvVar)
	if vaultAddr == "" {
		vaultAddr = fmt.Sprintf("https://127.0.0.1:%d", config.Port)
	}
	status.TLSEnabled = strings.HasPrefix(vaultAddr, "https://")
	
	// If unsealed, check auth methods and policies
	if status.Initialized && !status.Sealed {
		if rootToken, err := getRootToken(rc); err == nil {
			checkAuthAndPolicies(rc, status, rootToken)
		}
	}
	
	return status, nil
}

func checkAuthAndPolicies(rc *eos_io.RuntimeContext, status *VaultVerificationStatus, rootToken string) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Vault client
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		logger.Warn("Failed to read vault environment", zap.Error(err))
		return
	}
	
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		logger.Warn("Failed to create vault client", zap.Error(err))
		return
	}
	
	client.SetToken(rootToken)
	
	// Check auth methods
	if auths, err := client.Sys().ListAuth(); err == nil {
		for path := range auths {
			status.AuthMethods = append(status.AuthMethods, strings.TrimSuffix(path, "/"))
		}
		logger.Debug("Auth methods found", zap.Strings("methods", status.AuthMethods))
	}
	
	// Check policies
	if policies, err := client.Sys().ListPolicies(); err == nil {
		status.Policies = policies
		logger.Debug("Policies found", zap.Strings("policies", status.Policies))
	}
	
	// Check audit devices
	if audits, err := client.Sys().ListAudit(); err == nil && len(audits) > 0 {
		status.AuditEnabled = true
		logger.Debug("Audit devices found", zap.Int("count", len(audits)))
	}
}

func performVerificationChecks(rc *eos_io.RuntimeContext, config *SaltConfig, status *VaultVerificationStatus) (*VerificationResults, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	results := &VerificationResults{
		Status:  status,
		Issues:  []string{},
		Warnings: []string{},
	}
	
	// Binary check
	results.BinaryCheck = status.Installed
	if !results.BinaryCheck {
		results.Issues = append(results.Issues, "Vault binary not found")
	}
	
	// Service check
	results.ServiceCheck = status.ServiceActive
	if status.Installed && !results.ServiceCheck {
		results.Issues = append(results.Issues, "Vault service is not active")
	}
	
	// Configuration check
	configFile := filepath.Join(config.ConfigPath, VaultConfigFile)
	if _, err := os.Stat(configFile); err == nil {
		results.ConfigCheck = true
		logger.Debug("Configuration file found", zap.String("path", configFile))
	} else if status.Installed {
		results.Issues = append(results.Issues, fmt.Sprintf("Configuration file not found: %s", configFile))
	}
	
	// TLS check
	if status.Installed && results.ServiceCheck {
		results.TLSCheck = checkTLSConfiguration(rc, config)
		if !results.TLSCheck && !config.TLSDisable {
			results.Warnings = append(results.Warnings, "TLS appears to be disabled or misconfigured")
		}
	}
	
	// Network check
	if status.ServiceActive {
		results.NetworkCheck = checkNetworkConnectivity(rc, config)
		if !results.NetworkCheck {
			results.Issues = append(results.Issues, fmt.Sprintf("Vault API not accessible on port %d", config.Port))
		}
	}
	
	// Storage check
	results.StorageCheck = checkStorageConfiguration(rc, config)
	if !results.StorageCheck && status.Installed {
		results.Warnings = append(results.Warnings, "Storage directory issues detected")
	}
	
	// Permissions check
	results.PermissionsCheck = checkFilePermissions(rc, config)
	if !results.PermissionsCheck {
		results.Warnings = append(results.Warnings, "File permission issues detected")
	}
	
	// Audit check
	if status.Initialized && !status.Sealed {
		results.AuditCheck = status.AuditEnabled
		if !results.AuditCheck {
			results.Warnings = append(results.Warnings, "Audit logging is not enabled")
		}
	}
	
	// Backup check
	if config.BackupEnabled {
		results.BackupCheck = checkBackupConfiguration(rc, config)
		if !results.BackupCheck {
			results.Warnings = append(results.Warnings, "Backup configuration issues detected")
		}
	}
	
	return results, nil
}

func checkTLSConfiguration(rc *eos_io.RuntimeContext, config *SaltConfig) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	certFile := filepath.Join(config.TLSPath, "vault-cert.pem")
	keyFile := filepath.Join(config.TLSPath, "vault-key.pem")
	
	// Check if certificate files exist
	if _, err := os.Stat(certFile); err != nil {
		logger.Debug("TLS certificate not found", zap.String("path", certFile))
		return false
	}
	
	if _, err := os.Stat(keyFile); err != nil {
		logger.Debug("TLS key not found", zap.String("path", keyFile))
		return false
	}
	
	// Verify certificate validity
	cmd := exec.CommandContext(rc.Ctx, "openssl", "x509", "-in", certFile, "-noout", "-dates")
	if output, err := cmd.Output(); err == nil {
		logger.Debug("TLS certificate validity", zap.String("dates", string(output)))
		return true
	}
	
	return false
}

func checkNetworkConnectivity(rc *eos_io.RuntimeContext, config *SaltConfig) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if port is listening
	cmd := exec.CommandContext(rc.Ctx, "ss", "-tlpn")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to check listening ports", zap.Error(err))
		return false
	}
	
	portStr := fmt.Sprintf(":%d", config.Port)
	if strings.Contains(string(output), portStr) {
		logger.Debug("Vault port is listening", zap.Int("port", config.Port))
		return true
	}
	
	return false
}

func checkStorageConfiguration(rc *eos_io.RuntimeContext, config *SaltConfig) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check storage directory
	if info, err := os.Stat(config.StoragePath); err == nil {
		if !info.IsDir() {
			logger.Warn("Storage path is not a directory", zap.String("path", config.StoragePath))
			return false
		}
		
		// Check disk space
		cmd := exec.CommandContext(rc.Ctx, "df", "-h", config.StoragePath)
		if output, err := cmd.Output(); err == nil {
			logger.Debug("Storage disk usage", zap.String("output", string(output)))
		}
		
		return true
	}
	
	return false
}

func checkFilePermissions(rc *eos_io.RuntimeContext, config *SaltConfig) bool {
	logger := otelzap.Ctx(rc.Ctx)
	allGood := true
	
	// Check critical file permissions
	criticalFiles := map[string]os.FileMode{
		VaultInitDataFile: 0600,
		filepath.Join(config.TLSPath, "vault-key.pem"): 0600,
	}
	
	for path, expectedMode := range criticalFiles {
		if info, err := os.Stat(path); err == nil {
			actualMode := info.Mode().Perm()
			if actualMode != expectedMode {
				logger.Warn("Incorrect file permissions",
					zap.String("path", path),
					zap.String("expected", expectedMode.String()),
					zap.String("actual", actualMode.String()))
				allGood = false
			}
		}
	}
	
	return allGood
}

func checkBackupConfiguration(rc *eos_io.RuntimeContext, config *SaltConfig) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check backup directory
	if info, err := os.Stat(config.BackupPath); err != nil || !info.IsDir() {
		logger.Debug("Backup directory not found", zap.String("path", config.BackupPath))
		return false
	}
	
	// Check cron job
	cmd := exec.CommandContext(rc.Ctx, "crontab", "-l")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "vault") && strings.Contains(string(output), "backup") {
			logger.Debug("Backup cron job found")
			return true
		}
	}
	
	return false
}

func evaluateResults(rc *eos_io.RuntimeContext, results *VerificationResults) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check for critical issues
	if len(results.Issues) > 0 {
		logger.Error("Critical issues found during verification",
			zap.Strings("issues", results.Issues))
		return fmt.Errorf("verification found %d critical issues", len(results.Issues))
	}
	
	// Log warnings
	if len(results.Warnings) > 0 {
		logger.Warn("Warnings found during verification",
			zap.Strings("warnings", results.Warnings))
	}
	
	// Check overall health
	if !results.Status.Installed {
		return eos_err.NewUserError("Vault is not installed")
	}
	
	if results.Status.Installed && !results.ServiceCheck {
		logger.Warn("Vault is installed but service is not running")
	}
	
	if results.Status.Initialized && results.Status.Sealed {
		logger.Warn("Vault is initialized but sealed")
	}
	
	return nil
}

func displayVerificationSummary(rc *eos_io.RuntimeContext, results *VerificationResults) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== Vault Verification Summary ===")
	
	// Installation status
	logger.Info("Installation Status:",
		zap.Bool("installed", results.Status.Installed),
		zap.String("version", results.Status.Version),
		zap.Bool("service_active", results.Status.ServiceActive))
	
	// Configuration status
	logger.Info("Configuration Status:",
		zap.Bool("initialized", results.Status.Initialized),
		zap.Bool("sealed", results.Status.Sealed),
		zap.Bool("tls_enabled", results.Status.TLSEnabled))
	
	// Feature status
	if len(results.Status.AuthMethods) > 0 {
		logger.Info("Auth Methods:", zap.Strings("methods", results.Status.AuthMethods))
	}
	
	if len(results.Status.Policies) > 0 {
		logger.Info("Policies:", zap.Strings("policies", results.Status.Policies))
	}
	
	// Check results
	logger.Info("Verification Checks:",
		zap.Bool("binary", results.BinaryCheck),
		zap.Bool("service", results.ServiceCheck),
		zap.Bool("config", results.ConfigCheck),
		zap.Bool("tls", results.TLSCheck),
		zap.Bool("network", results.NetworkCheck),
		zap.Bool("storage", results.StorageCheck),
		zap.Bool("permissions", results.PermissionsCheck),
		zap.Bool("audit", results.AuditCheck),
		zap.Bool("backup", results.BackupCheck))
	
	// Issues and warnings
	if len(results.Issues) > 0 {
		logger.Error("Critical Issues:", zap.Strings("issues", results.Issues))
	}
	
	if len(results.Warnings) > 0 {
		logger.Warn("Warnings:", zap.Strings("warnings", results.Warnings))
	}
	
	// Overall status
	if len(results.Issues) == 0 && len(results.Warnings) == 0 {
		logger.Info("✓ Vault verification passed with no issues")
	} else if len(results.Issues) == 0 {
		logger.Info("✓ Vault verification passed with warnings")
	} else {
		logger.Error("✗ Vault verification failed")
	}
}