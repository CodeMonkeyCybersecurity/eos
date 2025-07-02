// cmd/secure/system.go

package secure

import (
	"encoding/json"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var systemSecureCmd = &cobra.Command{
	Use:   "system [target]",
	Short: "Apply comprehensive security hardening to target systems",
	Long: `Apply comprehensive security hardening to target systems using SaltStack.

This command follows the assessment→intervention→evaluation model:
1. Assessment: Evaluates current security posture
2. Intervention: Applies security hardening measures via SaltStack
3. Evaluation: Verifies security improvements

Examples:
  eos secure system "*"                    # Harden all minions
  eos secure system "web-servers"         # Harden web server group
  eos secure system "prod-*" --profile advanced    # Advanced hardening profile`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		profile, _ := cmd.Flags().GetString("profile")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Starting system security hardening",
			zap.String("target", target),
			zap.String("profile", profile),
			zap.Bool("dry_run", dryRun))

		// Assessment: Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Create security hardening manager
		securityManager := system.NewSecurityHardeningManager(saltManager, vaultPath)

		// Generate security configuration based on profile
		securityConfig := generateSecurityConfig(system.SecurityProfile(profile))

		if dryRun {
			logger.Info("Dry run mode - assessing security posture only")
			assessment, err := securityManager.AssessSecurityPosture(rc, target, securityConfig.Profile)
			if err != nil {
				return cerr.Wrap(err, "security assessment failed")
			}

			// Display assessment results
			displaySecurityAssessment(rc, assessment)
			return nil
		}

		// Intervention: Apply security hardening
		assessment, err := securityManager.HardenSystem(rc, target, securityConfig)
		if err != nil {
			return cerr.Wrap(err, "system hardening failed")
		}

		// Evaluation: Display results
		logger.Info("System security hardening completed",
			zap.Float64("compliance_score", assessment.ComplianceScore),
			zap.String("risk_level", assessment.RiskLevel),
			zap.Int("vulnerabilities_found", len(assessment.Vulnerabilities)),
			zap.Int("recommendations", len(assessment.Recommendations)))

		displaySecurityAssessment(rc, assessment)

		return nil
	}),
}

var twoFactorCmd = &cobra.Command{
	Use:   "2fa [target]",
	Short: "Setup two-factor authentication on target systems",
	Long: `Setup two-factor authentication (2FA) on target systems using SaltStack.

Supported 2FA methods:
- TOTP (Time-based One-Time Password) via Google Authenticator
- U2F (Universal 2nd Factor) hardware tokens
- FIDO2 WebAuthn

Examples:
  eos secure 2fa "*" --users alice,bob       # Setup 2FA for specific users
  eos secure 2fa "servers" --method totp     # Setup TOTP 2FA
  eos secure 2fa "prod-*" --enforce-ssh      # Enforce 2FA for SSH`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		method, _ := cmd.Flags().GetString("method")
		users, _ := cmd.Flags().GetStringSlice("users")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		enforceSSH, _ := cmd.Flags().GetBool("enforce-ssh")
		enforceSudo, _ := cmd.Flags().GetBool("enforce-sudo")

		logger.Info("Setting up two-factor authentication",
			zap.String("target", target),
			zap.String("method", method),
			zap.Strings("users", users))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Create security hardening manager
		securityManager := system.NewSecurityHardeningManager(saltManager, vaultPath)

		// Configure 2FA settings
		twoFactorConfig := &system.TwoFactorAuthConfig{
			Enabled:       true,
			Method:        method,
			RequiredUsers: users,
			EnforceSSH:    enforceSSH,
			EnforceSudo:   enforceSudo,
			BackupCodes:   true,
			TOTPSettings: system.TOTPConfig{
				Issuer:     "Eos Security",
				WindowSize: 3,
				SecretBits: 160,
				RateLimit:  3,
			},
		}

		// Apply 2FA configuration
		if err := securityManager.SetupTwoFactorAuthentication(rc, target, twoFactorConfig); err != nil {
			return cerr.Wrap(err, "two-factor authentication setup failed")
		}

		logger.Info("Two-factor authentication setup completed successfully")

		return nil
	}),
}

func generateSecurityConfig(profile system.SecurityProfile) *system.SecurityConfiguration {
	config := &system.SecurityConfiguration{
		Profile: profile,
	}

	// Configure based on security profile
	switch profile {
	case system.SecurityProfileBaseline:
		config.SSHConfig = system.SSHSecurityConfig{
			Port:                   22,
			PermitRootLogin:        false,
			PasswordAuthentication: true,
			PubkeyAuthentication:   true,
			MaxAuthTries:           3,
			Protocol:               2,
		}

	case system.SecurityProfileIntermediate:
		config.SSHConfig = system.SSHSecurityConfig{
			Port:                   2222,
			PermitRootLogin:        false,
			PasswordAuthentication: false,
			PubkeyAuthentication:   true,
			MaxAuthTries:           3,
			Protocol:               2,
			AllowTcpForwarding:     false,
			X11Forwarding:          false,
		}

	case system.SecurityProfileAdvanced:
		config.SSHConfig = system.SSHSecurityConfig{
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

	case system.SecurityProfileCompliance:
		config.SSHConfig = system.SSHSecurityConfig{
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
		config.AuditConfig = system.AuditConfig{
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
	config.FirewallConfig = system.FirewallConfig{
		DefaultPolicy: "deny",
		Rules: []system.FirewallRule{
			{Action: "allow", Protocol: "tcp", Port: fmt.Sprintf("%d", config.SSHConfig.Port), Source: "any", Comment: "SSH access"},
			{Action: "allow", Protocol: "tcp", Port: "80", Source: "any", Comment: "HTTP"},
			{Action: "allow", Protocol: "tcp", Port: "443", Source: "any", Comment: "HTTPS"},
		},
	}

	return config
}

func displaySecurityAssessment(rc *eos_io.RuntimeContext, assessment *system.SecurityAssessment) {
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

func init() {
	// Add system security hardening command
	systemSecureCmd.Flags().String("profile", "baseline", "Security profile: baseline, intermediate, advanced, compliance")
	systemSecureCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	systemSecureCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")
	systemSecureCmd.Flags().Bool("dry-run", false, "Perform assessment only without applying changes")

	// Add 2FA setup command
	twoFactorCmd.Flags().String("method", "totp", "2FA method: totp, u2f, fido2")
	twoFactorCmd.Flags().StringSlice("users", []string{}, "Users to enable 2FA for")
	twoFactorCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	twoFactorCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")
	twoFactorCmd.Flags().Bool("enforce-ssh", false, "Enforce 2FA for SSH authentication")
	twoFactorCmd.Flags().Bool("enforce-sudo", false, "Enforce 2FA for sudo commands")

	SecureCmd.AddCommand(systemSecureCmd)
	SecureCmd.AddCommand(twoFactorCmd)
}
