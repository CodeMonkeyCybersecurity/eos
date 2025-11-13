// pkg/security_config/config.go
package security_config

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityConfig represents a comprehensive security configuration
type SecurityConfig struct {
	Profile                system.SecurityProfile `json:"profile"`
	FirewallConfig         *FirewallConfig        `json:"firewall_config"`
	AuditConfig            *AuditConfig           `json:"audit_config"`
	TwoFactorAuthConfig    *TwoFactorAuthConfig   `json:"two_factor_auth_config"`
	AccessControlConfig    *AccessControlConfig   `json:"access_control_config"`
	EncryptionConfig       *EncryptionConfig      `json:"encryption_config"`
	ComplianceRequirements []string               `json:"compliance_requirements"`
}

// FirewallConfig represents firewall configuration
type FirewallConfig struct {
	Enabled      bool     `json:"enabled"`
	DefaultDeny  bool     `json:"default_deny"`
	AllowedPorts []int    `json:"allowed_ports"`
	AllowedIPs   []string `json:"allowed_ips"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled      bool     `json:"enabled"`
	LogLevel     string   `json:"log_level"`
	LogRetention int      `json:"log_retention_days"`
	MonitorPaths []string `json:"monitor_paths"`
	AuditRules   []string `json:"audit_rules"`
}

// TwoFactorAuthConfig represents 2FA configuration
type TwoFactorAuthConfig struct {
	Enabled       bool     `json:"enabled"`
	Method        string   `json:"method"`
	RequiredUsers []string `json:"required_users"`
	EnforceSSH    bool     `json:"enforce_ssh"`
	EnforceSudo   bool     `json:"enforce_sudo"`
	BackupCodes   bool     `json:"backup_codes"`
}

// AccessControlConfig represents access control configuration
type AccessControlConfig struct {
	StrictSSHConfig  bool            `json:"strict_ssh_config"`
	DisableRootLogin bool            `json:"disable_root_login"`
	PasswordPolicy   *PasswordPolicy `json:"password_policy"`
	SudoRestrictions []string        `json:"sudo_restrictions"`
}

// PasswordPolicy represents password requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireNumbers bool `json:"require_numbers"`
	RequireSymbols bool `json:"require_symbols"`
	MaxAge         int  `json:"max_age_days"`
}

// EncryptionConfig represents encryption settings
type EncryptionConfig struct {
	DiskEncryption bool     `json:"disk_encryption"`
	FileEncryption bool     `json:"file_encryption"`
	TLSVersion     string   `json:"tls_version"`
	CipherSuites   []string `json:"cipher_suites"`
}

// SecurityAssessment represents a security assessment result
// Use existing types from system package
type SecurityAssessment = system.SecurityAssessment
type SecurityVulnerability = system.SecurityVulnerability
type SecurityRecommendation = system.SecurityRecommendation

// GenerateSecurityConfig creates a security configuration based on the profile
// This follows the Assess → Intervene → Evaluate pattern
func GenerateSecurityConfig(rc *eos_io.RuntimeContext, profile system.SecurityProfile) (*SecurityConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing security configuration requirements",
		zap.String("profile", string(profile)))

	if profile == "" {
		profile = "baseline"
	}

	// INTERVENE - Generate configuration based on profile
	logger.Info("Generating security configuration")

	var config *SecurityConfig

	switch profile {
	case "baseline":
		config = generateBaselineConfig()
	case "intermediate":
		config = generateIntermediateConfig()
	case "advanced":
		config = generateAdvancedConfig()
	case "compliance":
		config = generateComplianceConfig()
	default:
		return nil, fmt.Errorf("unsupported security profile: %s", profile)
	}

	// Set the profile in the generated config
	config.Profile = profile

	// EVALUATE - Validate configuration
	logger.Info("Validating security configuration")

	if err := validateSecurityConfig(config); err != nil {
		return nil, fmt.Errorf("security configuration validation failed: %w", err)
	}

	logger.Info("Security configuration generated successfully",
		zap.String("profile", string(profile)))

	return config, nil
}

// DisplaySecurityAssessment shows security assessment results
func DisplaySecurityAssessment(rc *eos_io.RuntimeContext, assessment *system.SecurityAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Security Assessment Results",
		zap.Float64("compliance_score", assessment.ComplianceScore),
		zap.String("risk_level", assessment.RiskLevel),
		zap.Int("vulnerabilities", len(assessment.Vulnerabilities)),
		zap.Int("recommendations", len(assessment.Recommendations)))

	// Log vulnerabilities
	for _, vuln := range assessment.Vulnerabilities {
		logger.Warn("Security Vulnerability",
			zap.String("id", vuln.ID),
			zap.String("description", vuln.Description),
			zap.String("severity", vuln.Severity),
			zap.String("component", vuln.Component))
	}

	// Log recommendations
	for _, rec := range assessment.Recommendations {
		logger.Info("Security Recommendation",
			zap.String("description", rec.Description),
			zap.String("priority", rec.Priority),
			zap.String("category", rec.Category),
			zap.String("action", rec.Action))
	}

	return nil
}

// generateBaselineConfig creates a baseline security configuration
func generateBaselineConfig() *SecurityConfig {
	return &SecurityConfig{
		Profile: "baseline",
		FirewallConfig: &FirewallConfig{
			Enabled:      true,
			DefaultDeny:  false,
			AllowedPorts: []int{22, 80, 443},
		},
		AuditConfig: &AuditConfig{
			Enabled:      true,
			LogLevel:     "info",
			LogRetention: 30,
			MonitorPaths: []string{"/etc", "/var/log"},
		},
		AccessControlConfig: &AccessControlConfig{
			StrictSSHConfig:  true,
			DisableRootLogin: true,
			PasswordPolicy: &PasswordPolicy{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumbers: true,
				MaxAge:         90,
			},
		},
		EncryptionConfig: &EncryptionConfig{
			TLSVersion: "1.2",
		},
		ComplianceRequirements: []string{"basic"},
	}
}

// generateIntermediateConfig creates an intermediate security configuration
func generateIntermediateConfig() *SecurityConfig {
	config := generateBaselineConfig()
	config.Profile = "intermediate"
	config.FirewallConfig.DefaultDeny = true
	config.AuditConfig.LogLevel = "debug"
	config.AuditConfig.LogRetention = 60
	config.TwoFactorAuthConfig = &TwoFactorAuthConfig{
		Enabled:     true,
		Method:      "totp",
		EnforceSSH:  true,
		BackupCodes: true,
	}
	config.EncryptionConfig.TLSVersion = "1.3"
	config.ComplianceRequirements = []string{"basic", "cis"}
	return config
}

// generateAdvancedConfig creates an advanced security configuration
func generateAdvancedConfig() *SecurityConfig {
	config := generateIntermediateConfig()
	config.Profile = "advanced"
	config.TwoFactorAuthConfig.EnforceSudo = true
	config.AuditConfig.LogRetention = 365
	config.EncryptionConfig.DiskEncryption = true
	config.EncryptionConfig.FileEncryption = true
	config.ComplianceRequirements = []string{"basic", "cis", "nist"}
	return config
}

// generateComplianceConfig creates a compliance-focused security configuration
func generateComplianceConfig() *SecurityConfig {
	config := generateAdvancedConfig()
	config.Profile = "compliance"
	config.AuditConfig.LogRetention = 2555 // 7 years
	config.ComplianceRequirements = []string{"basic", "cis", "nist", "iso27001", "sox"}
	return config
}

// validateSecurityConfig validates the security configuration
func validateSecurityConfig(config *SecurityConfig) error {
	if config.Profile == "" {
		return fmt.Errorf("security profile is required")
	}

	if config.FirewallConfig != nil && len(config.FirewallConfig.AllowedPorts) == 0 {
		return fmt.Errorf("at least one allowed port must be specified")
	}

	if config.AuditConfig != nil && config.AuditConfig.LogRetention <= 0 {
		return fmt.Errorf("log retention must be greater than 0")
	}

	return nil
}

// ConvertToSystemSecurityConfiguration converts SecurityConfig to system.SecurityConfiguration
func ConvertToSystemSecurityConfiguration(config *SecurityConfig) *system.SecurityConfiguration {
	// Create a basic mapping - in a real implementation, you'd map all fields properly
	return &system.SecurityConfiguration{
		Profile: config.Profile,
		SSHConfig: system.SSHSecurityConfig{
			Port:                   22,
			PermitRootLogin:        false,
			PasswordAuthentication: false,
			PubkeyAuthentication:   true,
			MaxAuthTries:           3,
			ClientAliveInterval:    300,
			ClientAliveCountMax:    3,
			Protocol:               2,
			AllowTcpForwarding:     false,
			X11Forwarding:          false,
			UsePAM:                 true,
		},
		TwoFactorAuth: system.TwoFactorAuthConfig{
			Enabled:       config.TwoFactorAuthConfig.Enabled,
			Method:        config.TwoFactorAuthConfig.Method,
			RequiredUsers: config.TwoFactorAuthConfig.RequiredUsers,
			EnforceSSH:    config.TwoFactorAuthConfig.EnforceSSH,
			EnforceSudo:   config.TwoFactorAuthConfig.EnforceSudo,
			BackupCodes:   config.TwoFactorAuthConfig.BackupCodes,
		},
		FirewallConfig: system.FirewallConfig{
			DefaultPolicy: "DROP",
			Rules:         []system.FirewallRule{},
			Zones:         make(map[string][]string),
		},
		AuditConfig: system.AuditConfig{
			Enabled:        config.AuditConfig.Enabled,
			Rules:          config.AuditConfig.AuditRules,
			LogRotation:    config.AuditConfig.LogRetention,
			MaxLogSize:     "100MB",
			ActionOnFull:   "syslog",
			MonitoredPaths: config.AuditConfig.MonitorPaths,
		},
		// Add default values for other required fields
		UserSecurity: system.UserSecurityConfig{
			PasswordPolicy: system.PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				MinAge:           1,
				RememberHistory:  5,
			},
		},
		SystemSecurity: system.SystemSecurityConfig{
			KernelHardening: system.KernelHardening{
				DisableUnusedModules: []string{},
				SysctlParameters:     make(map[string]string),
			},
		},
		EmergencyAccess: system.EmergencyAccessConfig{
			// Add required fields based on actual type definition
		},
	}
}
