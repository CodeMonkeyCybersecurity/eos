// pkg/ldap/certificate.go
package ldap

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// LDAP certificate paths
	LDAPCertsDir = "/etc/ldap/certs"
	LDAPCertPath = "/etc/ldap/certs/ldap.crt"
	LDAPKeyPath  = "/etc/ldap/certs/ldap.key"

	// Certificate validity
	CertValidityDays = 365
	CertKeySize      = 2048
)

// RegenerateTLSCertificateConfig configures TLS certificate regeneration
type RegenerateTLSCertificateConfig struct {
	IPSAN  string // IP address to include in Subject Alternative Name
	DryRun bool   // If true, only show commands without executing
}

// ValidateIPAddress validates that the input is a valid IP address
// SECURITY: Prevents command injection attacks via IP address parameter
func ValidateIPAddress(ip string) error {
	// ASSESS - Check for basic IP format
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	// SECURITY: Additional check for shell metacharacters to prevent command injection
	// THREAT MODEL: User might try to inject commands via IP parameter
	// MITIGATION: Reject any IP containing shell metacharacters
	if matched, _ := regexp.MatchString(`[;&|<>$()\x00-\x1f\x7f-\x9f]`, ip); matched {
		return fmt.Errorf("IP address contains forbidden shell metacharacters")
	}

	return nil
}

// RegenerateTLSCertificate regenerates the LDAP TLS certificate with IP SAN
// PATTERN: Assess → Intervene → Evaluate
// SECURITY: Validates IP address input to prevent command injection
func RegenerateTLSCertificate(rc *eos_io.RuntimeContext, config *RegenerateTLSCertificateConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate configuration
	logger.Info("Assessing LDAP certificate regeneration request",
		zap.String("ip_san", config.IPSAN),
		zap.Bool("dry_run", config.DryRun))

	if config.IPSAN == "" {
		return fmt.Errorf("IP SAN address is required")
	}

	// SECURITY: Validate IP address to prevent command injection
	if err := ValidateIPAddress(config.IPSAN); err != nil {
		logger.Error("IP address validation failed",
			zap.String("ip", config.IPSAN),
			zap.Error(err))
		return fmt.Errorf("invalid IP address: %w", err)
	}

	logger.Info("IP address validated successfully",
		zap.String("ip_san", config.IPSAN))

	// INTERVENE - Build and execute commands
	// NOTE: Commands are executed via bash -c for complex shell operations
	// SECURITY: IP address has been validated to prevent injection
	cmds := []string{
		// Create certificate directory
		fmt.Sprintf("mkdir -p %s", LDAPCertsDir),

		// Generate new certificate with IP SAN
		// SECURITY: IP address is validated before inclusion in command
		fmt.Sprintf(`openssl req -x509 -nodes -days %d -newkey rsa:%d \
  -subj "/CN=%s" \
  -keyout %s \
  -out %s \
  -addext "subjectAltName = IP:%s"`,
			CertValidityDays,
			CertKeySize,
			config.IPSAN,
			LDAPKeyPath,
			LDAPCertPath,
			config.IPSAN),
	}

	logger.Info("Executing LDAP certificate regeneration",
		zap.Int("command_count", len(cmds)),
		zap.String("certs_dir", LDAPCertsDir))

	for i, cmdStr := range cmds {
		logger.Info("Executing command",
			zap.Int("step", i+1),
			zap.Int("total", len(cmds)),
			zap.String("command", cmdStr))

		if config.DryRun {
			logger.Info("DRY RUN: Would execute command",
				zap.String("command", cmdStr))
			continue
		}

		// Execute command
		cmd := exec.Command("bash", "-c", cmdStr)
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Error("Command execution failed",
				zap.String("command", cmdStr),
				zap.String("output", string(output)),
				zap.Error(err))
			return fmt.Errorf("failed to run command: %s: %w\nOutput: %s", cmdStr, err, string(output))
		}

		logger.Debug("Command executed successfully",
			zap.String("command", cmdStr),
			zap.String("output", string(output)))
	}

	// EVALUATE - Confirm success
	logger.Info("LDAP TLS certificate regenerated successfully",
		zap.String("certificate_path", LDAPCertPath),
		zap.String("key_path", LDAPKeyPath),
		zap.String("ip_san", config.IPSAN),
		zap.Int("validity_days", CertValidityDays))

	logger.Info("Reminder: Restart your LDAP server to use the new certificate",
		zap.String("command", "sudo systemctl restart slapd"))

	return nil
}
