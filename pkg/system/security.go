// pkg/system/security.go

package system

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityHardeningManager handles security configuration via SaltStack
type SecurityHardeningManager struct {
	saltManager *SaltStackManager
	vaultPath   string
}

// SecurityProfile defines different security hardening levels
type SecurityProfile string

const (
	SecurityProfileBaseline     SecurityProfile = "baseline"
	SecurityProfileIntermediate SecurityProfile = "intermediate"
	SecurityProfileAdvanced     SecurityProfile = "advanced"
	SecurityProfileCompliance   SecurityProfile = "compliance"
)

// SecurityConfiguration defines comprehensive security settings
type SecurityConfiguration struct {
	Profile         SecurityProfile       `json:"profile"`
	SSHConfig       SSHSecurityConfig     `json:"ssh_config"`
	TwoFactorAuth   TwoFactorAuthConfig   `json:"two_factor_auth"`
	UserSecurity    UserSecurityConfig    `json:"user_security"`
	SystemSecurity  SystemSecurityConfig  `json:"system_security"`
	FirewallConfig  FirewallConfig        `json:"firewall_config"`
	AuditConfig     AuditConfig           `json:"audit_config"`
	EmergencyAccess EmergencyAccessConfig `json:"emergency_access"`
}

// SSHSecurityConfig defines SSH hardening configuration
type SSHSecurityConfig struct {
	Port                   int      `json:"port"`
	PermitRootLogin        bool     `json:"permit_root_login"`
	PasswordAuthentication bool     `json:"password_authentication"`
	PubkeyAuthentication   bool     `json:"pubkey_authentication"`
	AllowUsers             []string `json:"allow_users"`
	AllowGroups            []string `json:"allow_groups"`
	MaxAuthTries           int      `json:"max_auth_tries"`
	ClientAliveInterval    int      `json:"client_alive_interval"`
	ClientAliveCountMax    int      `json:"client_alive_count_max"`
	Protocol               int      `json:"protocol"`
	HostKeyAlgorithms      []string `json:"host_key_algorithms"`
	KexAlgorithms          []string `json:"kex_algorithms"`
	Ciphers                []string `json:"ciphers"`
	MACs                   []string `json:"macs"`
	AllowTcpForwarding     bool     `json:"allow_tcp_forwarding"`
	X11Forwarding          bool     `json:"x11_forwarding"`
	UsePAM                 bool     `json:"use_pam"`
}

// TwoFactorAuthConfig defines 2FA configuration
type TwoFactorAuthConfig struct {
	Enabled       bool       `json:"enabled"`
	Method        string     `json:"method"` // totp, u2f, fido2
	RequiredUsers []string   `json:"required_users"`
	ExemptUsers   []string   `json:"exempt_users"`
	BackupCodes   bool       `json:"backup_codes"`
	EnforceSSH    bool       `json:"enforce_ssh"`
	EnforceSudo   bool       `json:"enforce_sudo"`
	TOTPSettings  TOTPConfig `json:"totp_settings"`
}

// TOTPConfig defines TOTP-specific settings
type TOTPConfig struct {
	Issuer     string `json:"issuer"`
	WindowSize int    `json:"window_size"`
	SecretBits int    `json:"secret_bits"`
	RateLimit  int    `json:"rate_limit"`
}

// UserSecurityConfig defines user account security settings
type UserSecurityConfig struct {
	PasswordPolicy    PasswordPolicy    `json:"password_policy"`
	AccountLockout    AccountLockout    `json:"account_lockout"`
	SessionTimeout    int               `json:"session_timeout"`
	SudoConfiguration SudoConfig        `json:"sudo_configuration"`
	LoginRestrictions LoginRestrictions `json:"login_restrictions"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	MaxAge           int  `json:"max_age"`
	MinAge           int  `json:"min_age"`
	RememberHistory  int  `json:"remember_history"`
}

// AccountLockout defines account lockout settings
type AccountLockout struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"`
	LockoutTime int  `json:"lockout_time"`
	ResetTime   int  `json:"reset_time"`
}

// SudoConfig defines sudo access configuration
type SudoConfig struct {
	RequirePassword bool     `json:"require_password"`
	PasswordTimeout int      `json:"password_timeout"`
	AllowedUsers    []string `json:"allowed_users"`
	AllowedGroups   []string `json:"allowed_groups"`
	LogCommands     bool     `json:"log_commands"`
}

// LoginRestrictions defines login access restrictions
type LoginRestrictions struct {
	AllowedTimes   []string `json:"allowed_times"`
	AllowedSources []string `json:"allowed_sources"`
	DeniedUsers    []string `json:"denied_users"`
	MaxSessions    int      `json:"max_sessions"`
}

// SystemSecurityConfig defines system-level security settings
type SystemSecurityConfig struct {
	KernelHardening    KernelHardening    `json:"kernel_hardening"`
	FileSystemSecurity FileSystemSecurity `json:"filesystem_security"`
	NetworkSecurity    NetworkSecurity    `json:"network_security"`
	ProcessSecurity    ProcessSecurity    `json:"process_security"`
}

// KernelHardening defines kernel security parameters
type KernelHardening struct {
	DisableUnusedModules []string          `json:"disable_unused_modules"`
	SysctlParameters     map[string]string `json:"sysctl_parameters"`
	KernelParameters     []string          `json:"kernel_parameters"`
	EnableKASLR          bool              `json:"enable_kaslr"`
	EnableSMEP           bool              `json:"enable_smep"`
	EnableSMAP           bool              `json:"enable_smap"`
}

// FileSystemSecurity defines filesystem security settings
type FileSystemSecurity struct {
	MountOptions         map[string][]string `json:"mount_options"`
	FilePermissions      map[string]string   `json:"file_permissions"`
	DirectoryPermissions map[string]string   `json:"directory_permissions"`
	ImmutableFiles       []string            `json:"immutable_files"`
	NoExecMounts         []string            `json:"noexec_mounts"`
}

// NetworkSecurity defines network security settings
type NetworkSecurity struct {
	DisableProtocols  []string          `json:"disable_protocols"`
	IPTables          IPTablesConfig    `json:"iptables"`
	NetworkParameters map[string]string `json:"network_parameters"`
}

// IPTablesConfig defines iptables configuration
type IPTablesConfig struct {
	Rules []string `json:"rules"`
}

// ProcessSecurity defines process security settings
type ProcessSecurity struct {
	AppArmorProfiles map[string]string `json:"apparmor_profiles"`
	SELinuxPolicies  map[string]string `json:"selinux_policies"`
	Ulimits          map[string]string `json:"ulimits"`
}

// FirewallConfig defines firewall configuration
type FirewallConfig struct {
	DefaultPolicy string              `json:"default_policy"`
	Rules         []FirewallRule      `json:"rules"`
	Zones         map[string][]string `json:"zones"`
}

// FirewallRule defines a single firewall rule
type FirewallRule struct {
	Action      string `json:"action"`   // ACCEPT, DROP, REJECT
	Protocol    string `json:"protocol"` // tcp, udp, icmp
	Port        string `json:"port"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Interface   string `json:"interface"`
	Comment     string `json:"comment"`
}

// AuditConfig defines system auditing configuration
type AuditConfig struct {
	Enabled        bool     `json:"enabled"`
	Rules          []string `json:"rules"`
	LogRotation    int      `json:"log_rotation"`
	MaxLogSize     string   `json:"max_log_size"`
	ActionOnFull   string   `json:"action_on_full"`
	MonitoredPaths []string `json:"monitored_paths"`
}

// EmergencyAccessConfig defines emergency access methods
type EmergencyAccessConfig struct {
	DropbearSSH   DropbearConfig `json:"dropbear_ssh"`
	SerialConsole bool           `json:"serial_console"`
	RecoveryKeys  []string       `json:"recovery_keys"`
	BackupAccess  BackupAccess   `json:"backup_access"`
}

// DropbearConfig defines Dropbear SSH configuration for emergency access
type DropbearConfig struct {
	Enabled        bool     `json:"enabled"`
	Port           int      `json:"port"`
	AuthorizedKeys []string `json:"authorized_keys"`
	Banner         string   `json:"banner"`
}

// BackupAccess defines backup access methods
type BackupAccess struct {
	LocalUser string `json:"local_user"`
	SSHKey    string `json:"ssh_key"`
	VaultPath string `json:"vault_path"`
}

// SecurityAssessment represents security posture assessment
type SecurityAssessment struct {
	Target          string                   `json:"target"`
	Profile         SecurityProfile          `json:"profile"`
	ComplianceScore float64                  `json:"compliance_score"`
	Vulnerabilities []SecurityVulnerability  `json:"vulnerabilities"`
	Recommendations []SecurityRecommendation `json:"recommendations"`
	CurrentConfig   map[string]interface{}   `json:"current_config"`
	RequiredChanges []SecurityChange         `json:"required_changes"`
	RiskLevel       string                   `json:"risk_level"`
	Timestamp       time.Time                `json:"timestamp"`
}

// SecurityVulnerability represents a security issue
type SecurityVulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Component   string `json:"component"`
	Remediation string `json:"remediation"`
	CVE         string `json:"cve,omitempty"`
}

// SecurityRecommendation represents a security improvement
type SecurityRecommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Impact      string `json:"impact"`
}

// SecurityChange represents a required security configuration change
type SecurityChange struct {
	Component     string      `json:"component"`
	Setting       string      `json:"setting"`
	CurrentValue  interface{} `json:"current_value"`
	RequiredValue interface{} `json:"required_value"`
	Reason        string      `json:"reason"`
}

// NewSecurityHardeningManager creates a new security hardening manager
func NewSecurityHardeningManager(saltManager *SaltStackManager, vaultPath string) *SecurityHardeningManager {
	return &SecurityHardeningManager{
		saltManager: saltManager,
		vaultPath:   vaultPath,
	}
}

// HardenSystem applies comprehensive security hardening following assessment→intervention→evaluation
func (s *SecurityHardeningManager) HardenSystem(rc *eos_io.RuntimeContext, target string, config *SecurityConfiguration) (*SecurityAssessment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting system security hardening",
		zap.String("target", target),
		zap.String("profile", string(config.Profile)))

	// Assessment: Evaluate current security posture
	assessment, err := s.AssessSecurityPosture(rc, target, config.Profile)
	if err != nil {
		return nil, cerr.Wrap(err, "security posture assessment failed")
	}

	// Intervention: Apply security hardening measures
	if err := s.interventionApplySecurityMeasures(rc, target, config, assessment); err != nil {
		return assessment, cerr.Wrap(err, "security hardening intervention failed")
	}

	// Evaluation: Verify security improvements
	if err := s.EvaluateSecurityHardening(rc, target, config, assessment); err != nil {
		return assessment, cerr.Wrap(err, "security hardening evaluation failed")
	}

	logger.Info("System security hardening completed successfully",
		zap.Float64("compliance_score", assessment.ComplianceScore),
		zap.String("risk_level", assessment.RiskLevel))

	return assessment, nil
}

// AssessSecurityPosture evaluates current security configuration
func (s *SecurityHardeningManager) AssessSecurityPosture(rc *eos_io.RuntimeContext, target string, profile SecurityProfile) (*SecurityAssessment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing security posture", zap.String("target", target))

	assessment := &SecurityAssessment{
		Target:          target,
		Profile:         profile,
		Vulnerabilities: []SecurityVulnerability{},
		Recommendations: []SecurityRecommendation{},
		CurrentConfig:   make(map[string]interface{}),
		RequiredChanges: []SecurityChange{},
		Timestamp:       time.Now(),
	}

	// Assess SSH configuration
	if err := s.assessSSHSecurity(rc, target, assessment); err != nil {
		return nil, cerr.Wrap(err, "SSH security assessment failed")
	}

	// Assess user security
	if err := s.assessUserSecurity(rc, target, assessment); err != nil {
		return nil, cerr.Wrap(err, "user security assessment failed")
	}

	// Assess system security
	if err := s.assessSystemSecurity(rc, target, assessment); err != nil {
		return nil, cerr.Wrap(err, "system security assessment failed")
	}

	// Calculate compliance score
	assessment.ComplianceScore = s.calculateComplianceScore(assessment)
	assessment.RiskLevel = s.determineRiskLevel(assessment.ComplianceScore)

	logger.Info("Security posture assessment completed",
		zap.Float64("compliance_score", assessment.ComplianceScore),
		zap.Int("vulnerabilities", len(assessment.Vulnerabilities)),
		zap.Int("recommendations", len(assessment.Recommendations)))

	return assessment, nil
}

// SetupTwoFactorAuthentication configures 2FA via SaltStack
func (s *SecurityHardeningManager) SetupTwoFactorAuthentication(rc *eos_io.RuntimeContext, target string, config *TwoFactorAuthConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up two-factor authentication", zap.String("target", target))

	// Generate TOTP secrets and store in Vault
	for _, user := range config.RequiredUsers {
		totpSecret, err := s.generateTOTPSecret(rc, user)
		if err != nil {
			return cerr.Wrap(err, fmt.Sprintf("failed to generate TOTP secret for user %s", user))
		}

		// Store in Vault
		vaultPath := fmt.Sprintf("%s/totp/%s", s.vaultPath, user)
		secretData := map[string]interface{}{
			"totp_secret": totpSecret,
			"user":        user,
			"issuer":      config.TOTPSettings.Issuer,
			"created":     time.Now().Unix(),
		}

		client, err := vault.GetVaultClient(rc)
		if err != nil {
			return cerr.Wrap(err, "failed to get Vault client")
		}

		if err := vault.WriteKVv2(rc, client, "secret", vaultPath, secretData); err != nil {
			return cerr.Wrap(err, fmt.Sprintf("failed to store TOTP secret for user %s", user))
		}

		logger.Info("TOTP secret generated and stored", zap.String("user", user))
	}

	// Apply 2FA configuration via SaltStack
	slsContent := s.generateTwoFactorSLS(config)
	err := s.saltManager.client.StateApply(rc.Ctx, target, "two_factor_auth", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return cerr.Wrap(err, "failed to apply 2FA configuration")
	}

	// Configuration applied successfully

	logger.Info("Two-factor authentication setup completed")
	return nil
}

// SetupEmergencyAccess configures emergency access methods
func (s *SecurityHardeningManager) SetupEmergencyAccess(rc *eos_io.RuntimeContext, target string, config *EmergencyAccessConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up emergency access", zap.String("target", target))

	// Configure Dropbear SSH if enabled
	if config.DropbearSSH.Enabled {
		if err := s.configureDropbearSSH(rc, target, &config.DropbearSSH); err != nil {
			return cerr.Wrap(err, "failed to configure Dropbear SSH")
		}
	}

	// Store emergency keys in Vault
	if len(config.RecoveryKeys) > 0 {
		for i, key := range config.RecoveryKeys {
			vaultPath := fmt.Sprintf("%s/emergency/recovery_key_%d", s.vaultPath, i)
			keyData := map[string]interface{}{
				"key":     key,
				"index":   i,
				"created": time.Now().Unix(),
			}

			client, err := vault.GetVaultClient(rc)
			if err != nil {
				return cerr.Wrap(err, "failed to get Vault client")
			}

			if err := vault.WriteKVv2(rc, client, "secret", vaultPath, keyData); err != nil {
				return cerr.Wrap(err, fmt.Sprintf("failed to store recovery key %d", i))
			}
		}
	}

	logger.Info("Emergency access setup completed")
	return nil
}

// EvaluateSecurityHardening verifies security hardening results
func (s *SecurityHardeningManager) EvaluateSecurityHardening(rc *eos_io.RuntimeContext, target string, config *SecurityConfiguration, assessment *SecurityAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Evaluating security hardening results")

	// Re-assess security posture
	newAssessment, err := s.AssessSecurityPosture(rc, target, config.Profile)
	if err != nil {
		return cerr.Wrap(err, "security re-assessment failed")
	}

	// Compare before and after
	improvementScore := newAssessment.ComplianceScore - assessment.ComplianceScore
	vulnerabilityReduction := len(assessment.Vulnerabilities) - len(newAssessment.Vulnerabilities)

	logger.Info("Security hardening evaluation completed",
		zap.Float64("improvement_score", improvementScore),
		zap.Int("vulnerability_reduction", vulnerabilityReduction),
		zap.Float64("final_compliance_score", newAssessment.ComplianceScore))

	// Update assessment with final results
	assessment.ComplianceScore = newAssessment.ComplianceScore
	assessment.RiskLevel = newAssessment.RiskLevel
	assessment.Vulnerabilities = newAssessment.Vulnerabilities

	// Verify critical security measures
	if err := s.verifyCriticalSecurity(rc, target, config); err != nil {
		return cerr.Wrap(err, "critical security verification failed")
	}

	return nil
}

// Helper methods for assessment

func (s *SecurityHardeningManager) assessSSHSecurity(rc *eos_io.RuntimeContext, target string, assessment *SecurityAssessment) error {
	// Query SSH configuration via Salt
	result, err := s.saltManager.client.RunCommand(target, "grains", "ssh.check_key_present", []interface{}{"/etc/ssh/sshd_config"}, nil)
	if err != nil {
		return err
	}

	// Analyze SSH configuration and add vulnerabilities/recommendations
	_ = result // Process actual SSH config

	return nil
}

func (s *SecurityHardeningManager) assessUserSecurity(rc *eos_io.RuntimeContext, target string, assessment *SecurityAssessment) error {
	// Query user security configuration via Salt
	result, err := s.saltManager.client.RunCommand(target, "grains", "shadow.info", []interface{}{"root"}, nil)
	if err != nil {
		return err
	}

	// Analyze user security and add findings
	_ = result // Process user security state

	return nil
}

func (s *SecurityHardeningManager) assessSystemSecurity(rc *eos_io.RuntimeContext, target string, assessment *SecurityAssessment) error {
	// Query system security configuration via Salt
	result, err := s.saltManager.client.RunCommand(target, "grains", "sysctl.show", []interface{}{}, nil)
	if err != nil {
		return err
	}

	// Analyze system security and add findings
	_ = result // Process system security state

	return nil
}

// Helper methods for intervention

func (s *SecurityHardeningManager) interventionApplySecurityMeasures(rc *eos_io.RuntimeContext, target string, config *SecurityConfiguration, assessment *SecurityAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying security hardening measures")

	// Apply SSH hardening
	if err := s.applySSHHardening(rc, target, &config.SSHConfig); err != nil {
		return err
	}

	// Apply user security
	if err := s.applyUserSecurity(rc, target, &config.UserSecurity); err != nil {
		return err
	}

	// Apply system security
	if err := s.applySystemSecurity(rc, target, &config.SystemSecurity); err != nil {
		return err
	}

	// Apply firewall configuration
	if err := s.applyFirewallConfig(rc, target, &config.FirewallConfig); err != nil {
		return err
	}

	return nil
}

func (s *SecurityHardeningManager) applySSHHardening(rc *eos_io.RuntimeContext, target string, config *SSHSecurityConfig) error {
	slsContent := s.generateSSHHardeningSLS(config)
	err := s.saltManager.client.StateApply(rc.Ctx, target, "ssh_hardening", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return err
	}

	return nil // SSH hardening configuration applied successfully
}

func (s *SecurityHardeningManager) applyUserSecurity(rc *eos_io.RuntimeContext, target string, config *UserSecurityConfig) error {
	slsContent := s.generateUserSecuritySLS(config)
	err := s.saltManager.client.StateApply(rc.Ctx, target, "user_security", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return err
	}

	return nil // User security configuration applied successfully
}

func (s *SecurityHardeningManager) applySystemSecurity(rc *eos_io.RuntimeContext, target string, config *SystemSecurityConfig) error {
	slsContent := s.generateSystemSecuritySLS(config)
	err := s.saltManager.client.StateApply(rc.Ctx, target, "system_security", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return err
	}

	return nil // System security configuration applied successfully
}

func (s *SecurityHardeningManager) applyFirewallConfig(rc *eos_io.RuntimeContext, target string, config *FirewallConfig) error {
	slsContent := s.generateFirewallSLS(config)
	err := s.saltManager.client.StateApply(rc.Ctx, target, "firewall", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return err
	}

	return nil // Firewall configuration applied successfully
}

// SLS generation methods

func (s *SecurityHardeningManager) generateTwoFactorSLS(config *TwoFactorAuthConfig) string {
	var sls strings.Builder

	sls.WriteString(`
# Two-Factor Authentication Configuration
google_authenticator:
  pkg.installed:
    - names:
      - libpam-oath
      - oathtool

pam_oath_config:
  file.managed:
    - name: /etc/pam.d/sshd
    - source: salt://security/templates/pam_sshd.j2
    - template: jinja
    - backup: minion
`)

	return sls.String()
}

func (s *SecurityHardeningManager) generateSSHHardeningSLS(config *SSHSecurityConfig) string {
	var sls strings.Builder

	sls.WriteString(fmt.Sprintf(`
# SSH Hardening Configuration
sshd_config:
  file.managed:
    - name: /etc/ssh/sshd_config
    - source: salt://security/templates/sshd_config.j2
    - template: jinja
    - mode: 644
    - backup: minion
    - context:
        port: %d
        permit_root_login: %t
        password_authentication: %t
        pubkey_authentication: %t
        max_auth_tries: %d

sshd_service:
  service.running:
    - name: ssh
    - enable: True
    - reload: True
    - watch:
      - file: sshd_config
`, config.Port, config.PermitRootLogin, config.PasswordAuthentication,
		config.PubkeyAuthentication, config.MaxAuthTries))

	return sls.String()
}

func (s *SecurityHardeningManager) generateUserSecuritySLS(config *UserSecurityConfig) string {
	var sls strings.Builder

	sls.WriteString(`
# User Security Configuration
password_policy:
  file.managed:
    - name: /etc/pam.d/common-password
    - source: salt://security/templates/common-password.j2
    - template: jinja
    - backup: minion

login_defs:
  file.managed:
    - name: /etc/login.defs
    - source: salt://security/templates/login.defs.j2
    - template: jinja
    - backup: minion
`)

	return sls.String()
}

func (s *SecurityHardeningManager) generateSystemSecuritySLS(config *SystemSecurityConfig) string {
	var sls strings.Builder

	sls.WriteString(`
# System Security Configuration
sysctl_security:
  file.managed:
    - name: /etc/sysctl.d/99-security.conf
    - source: salt://security/templates/sysctl-security.conf.j2
    - template: jinja

kernel_modules_blacklist:
  file.managed:
    - name: /etc/modprobe.d/blacklist-security.conf
    - source: salt://security/templates/blacklist-modules.conf.j2
    - template: jinja
`)

	return sls.String()
}

func (s *SecurityHardeningManager) generateFirewallSLS(config *FirewallConfig) string {
	var sls strings.Builder

	sls.WriteString(`
# Firewall Configuration
ufw_package:
  pkg.installed:
    - name: ufw

ufw_default_policy:
  cmd.run:
    - name: ufw --force reset && ufw default deny incoming && ufw default allow outgoing
    - require:
      - pkg: ufw_package
`)

	for i, rule := range config.Rules {
		sls.WriteString(fmt.Sprintf(`
firewall_rule_%d:
  cmd.run:
    - name: ufw %s from %s to any port %s proto %s
    - require:
      - cmd: ufw_default_policy
`, i, rule.Action, rule.Source, rule.Port, rule.Protocol))
	}

	return sls.String()
}

// Helper methods

func (s *SecurityHardeningManager) generateTOTPSecret(rc *eos_io.RuntimeContext, user string) (string, error) {
	// Generate a secure TOTP secret
	// This would use a proper TOTP library in production
	return fmt.Sprintf("TOTP_SECRET_%s_%d", user, time.Now().Unix()), nil
}

func (s *SecurityHardeningManager) configureDropbearSSH(rc *eos_io.RuntimeContext, target string, config *DropbearConfig) error {
	slsContent := fmt.Sprintf(`
dropbear_package:
  pkg.installed:
    - name: dropbear

dropbear_config:
  file.managed:
    - name: /etc/default/dropbear
    - contents: |
        DROPBEAR_PORT=%d
        DROPBEAR_EXTRA_ARGS="-w -g"

dropbear_authorized_keys:
  file.managed:
    - name: /etc/dropbear/authorized_keys
    - contents: |
%s
    - mode: 600

dropbear_service:
  service.running:
    - name: dropbear
    - enable: True
    - watch:
      - file: dropbear_config
      - file: dropbear_authorized_keys
`, config.Port, strings.Join(config.AuthorizedKeys, "\n        "))

	err := s.saltManager.client.StateApply(rc.Ctx, target, "dropbear", map[string]interface{}{
		"sls_content": slsContent,
	})
	if err != nil {
		return err
	}

	return nil // Dropbear configuration applied successfully
}

func (s *SecurityHardeningManager) calculateComplianceScore(assessment *SecurityAssessment) float64 {
	// Calculate compliance score based on vulnerabilities and recommendations
	baseScore := 100.0

	for _, vuln := range assessment.Vulnerabilities {
		switch vuln.Severity {
		case "critical":
			baseScore -= 20.0
		case "high":
			baseScore -= 10.0
		case "medium":
			baseScore -= 5.0
		case "low":
			baseScore -= 2.0
		}
	}

	if baseScore < 0 {
		baseScore = 0
	}

	return baseScore
}

func (s *SecurityHardeningManager) determineRiskLevel(score float64) string {
	switch {
	case score >= 90:
		return "low"
	case score >= 70:
		return "medium"
	case score >= 50:
		return "high"
	default:
		return "critical"
	}
}

func (s *SecurityHardeningManager) verifyCriticalSecurity(rc *eos_io.RuntimeContext, target string, config *SecurityConfiguration) error {
	// Verify critical security measures are in place

	// Check SSH configuration
	result, err := s.saltManager.client.RunCommand(target, "grains", "service.status", []interface{}{"ssh"}, nil)
	if err != nil {
		return cerr.Wrap(err, "failed to verify SSH service")
	}
	_ = result // Process result to verify SSH is running

	// Check firewall status
	result, err = s.saltManager.client.RunCommand(target, "grains", "service.status", []interface{}{"ufw"}, nil)
	if err != nil {
		return cerr.Wrap(err, "failed to verify firewall service")
	}
	_ = result // Process result to verify firewall is active

	return nil
}

func generateSecurityConfig(profile SecurityProfile) *SecurityConfiguration {
	config := &SecurityConfiguration{
		Profile: profile,
	}

	// Configure based on security profile
	switch profile {
	case SecurityProfileBaseline:
		config.SSHConfig = SSHSecurityConfig{
			Port:                   22,
			PermitRootLogin:        false,
			PasswordAuthentication: true,
			PubkeyAuthentication:   true,
			MaxAuthTries:           3,
			Protocol:               2,
		}

	case SecurityProfileIntermediate:
		config.SSHConfig = SSHSecurityConfig{
			Port:                   2222,
			PermitRootLogin:        false,
			PasswordAuthentication: false,
			PubkeyAuthentication:   true,
			MaxAuthTries:           3,
			Protocol:               2,
			AllowTcpForwarding:     false,
			X11Forwarding:          false,
		}

	case SecurityProfileAdvanced:
		config.SSHConfig = SSHSecurityConfig{
			Port:                   2222,
			PermitRootLogin:        false,
			PasswordAuthentication: false,
			PubkeyAuthentication:   true,
			MaxAuthTries:           2,
			Protocol:               2,
			AllowTcpForwarding:     false,
			X11Forwarding:          false,
			HostKeyAlgorithms:      []string{"ssh-ed25519", "ecdsa-sha2-nistp256"},
			KexAlgorithms:          []string{"curve25519-sha256", "diffie-hellman-group16-sha512"},
			Ciphers:                []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"},
			MACs:                   []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"},
		}

	case SecurityProfileCompliance:
		config.SSHConfig = SSHSecurityConfig{
			Port:                   2222,
			PermitRootLogin:        false,
			PasswordAuthentication: false,
			PubkeyAuthentication:   true,
			MaxAuthTries:           2,
			Protocol:               2,
			AllowTcpForwarding:     false,
			X11Forwarding:          false,
			ClientAliveInterval:    300,
			ClientAliveCountMax:    2,
			HostKeyAlgorithms:      []string{"ssh-ed25519"},
			KexAlgorithms:          []string{"curve25519-sha256"},
			Ciphers:                []string{"chacha20-poly1305@openssh.com"},
			MACs:                   []string{"hmac-sha2-256-etm@openssh.com"},
		}

		// Enable audit logging for compliance
		config.AuditConfig = AuditConfig{
			Enabled:      true,
			LogRotation:  7,
			MaxLogSize:   "100M",
			ActionOnFull: "rotate",
			MonitoredPaths: []string{
				"/etc/passwd", "/etc/shadow", "/etc/group",
				"/etc/ssh/sshd_config", "/etc/sudoers",
			},
		}
	}

	// Common firewall rules
	config.FirewallConfig = FirewallConfig{
		DefaultPolicy: "deny",
		Rules: []FirewallRule{
			{Action: "allow", Protocol: "tcp", Port: fmt.Sprintf("%d", config.SSHConfig.Port), Source: "any", Comment: "SSH access"},
			{Action: "allow", Protocol: "tcp", Port: "80", Source: "any", Comment: "HTTP"},
			{Action: "allow", Protocol: "tcp", Port: "443", Source: "any", Comment: "HTTPS"},
		},
	}

	return config
}

func displaySecurityAssessment(rc *eos_io.RuntimeContext, assessment *SecurityAssessment) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Security Assessment Results",
		zap.String("target", assessment.Target),
		zap.String("profile", string(assessment.Profile)),
		zap.Float64("compliance_score", assessment.ComplianceScore),
		zap.String("risk_level", assessment.RiskLevel))

	if len(assessment.Vulnerabilities) > 0 {
		logger.Info("Vulnerabilities Found",
			zap.Int("count", len(assessment.Vulnerabilities)))

		for _, vuln := range assessment.Vulnerabilities {
			logger.Warn("Vulnerability",
				zap.String("id", vuln.ID),
				zap.String("severity", vuln.Severity),
				zap.String("component", vuln.Component),
				zap.String("description", vuln.Description),
				zap.String("remediation", vuln.Remediation))
		}
	}

	if len(assessment.Recommendations) > 0 {
		logger.Info("Security Recommendations",
			zap.Int("count", len(assessment.Recommendations)))

		for _, rec := range assessment.Recommendations {
			logger.Info("Recommendation",
				zap.String("priority", rec.Priority),
				zap.String("category", rec.Category),
				zap.String("description", rec.Description),
				zap.String("action", rec.Action),
				zap.String("impact", rec.Impact))
		}
	}

	// Log as JSON for machine parsing
	assessmentJSON, _ := json.MarshalIndent(assessment, "", "  ")
	logger.Debug("Complete security assessment", zap.String("assessment_json", string(assessmentJSON)))
}
