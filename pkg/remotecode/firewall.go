// pkg/remotecode/firewall.go
// Firewall configuration for remote IDE development

package remotecode

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureFirewall sets up firewall rules for SSH remote development
// Ensures SSH (port 22) is accessible from trusted networks
func ConfigureFirewall(rc *eos_io.RuntimeContext, config *Config, result *InstallResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring firewall for remote IDE development")

	if config.SkipFirewall {
		logger.Info("Skipping firewall configuration (--skip-firewall)")
		return nil
	}

	// Check if UFW is installed
	ufwStatus, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: FirewallTimeout,
	})
	if err != nil {
		logger.Warn("UFW not installed or accessible, skipping firewall configuration",
			zap.Error(err))
		result.Warnings = append(result.Warnings,
			"UFW not available - firewall configuration skipped")
		return nil
	}

	// CRITICAL: Ensure SSH is allowed BEFORE enabling UFW
	// This prevents lockout scenarios
	logger.Info("Ensuring SSH access is allowed before any other firewall changes")
	if err := ensureSSHAllowed(rc); err != nil {
		return fmt.Errorf("failed to ensure SSH access: %w", err)
	}
	result.FirewallRulesAdded = append(result.FirewallRulesAdded, fmt.Sprintf("%d/tcp (SSH)", shared.PortSSH))

	// Enable UFW if not active
	if !strings.Contains(ufwStatus, "Status: active") {
		logger.Info("Enabling UFW firewall")
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ufw",
			Args:    []string{"--force", "enable"},
			Timeout: FirewallTimeout,
		}); err != nil {
			return fmt.Errorf("failed to enable UFW: %w", err)
		}
	}

	// Define networks to allow SSH from
	networks := []string{
		TailscaleNetwork, // 100.64.0.0/10 - Tailscale CGNAT
		LocalNetworkA,    // 192.168.0.0/16 - Common LAN
		LocalNetworkB,    // 10.0.0.0/8 - Large private network
		LocalNetworkC,    // 172.16.0.0/12 - Docker/K8s networks
	}

	// Add user-specified networks
	networks = append(networks, config.AllowedNetworks...)

	// Add rules for SSH from each network
	for _, network := range networks {
		logger.Info("Adding SSH firewall rule",
			zap.String("network", network),
			zap.Int("port", shared.PortSSH))

		ruleArgs := []string{
			"allow", "from", network, "to", "any", "port", fmt.Sprintf("%d", shared.PortSSH),
		}

		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ufw",
			Args:    ruleArgs,
			Timeout: FirewallTimeout,
		}); err != nil {
			logger.Warn("Failed to add firewall rule",
				zap.String("network", network),
				zap.Error(err))
			// Continue with other networks
		} else {
			result.FirewallRulesAdded = append(result.FirewallRulesAdded,
				fmt.Sprintf("SSH from %s", network))
		}
	}

	// Reload firewall
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"reload"},
		Timeout: FirewallTimeout,
	}); err != nil {
		logger.Warn("Failed to reload firewall", zap.Error(err))
	}

	// Log current SSH-related rules
	logSSHRules(rc)

	return nil
}

// ensureSSHAllowed makes sure basic SSH access is allowed
// This is a safety measure to prevent lockout
func ensureSSHAllowed(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Allow SSH port (this is idempotent in UFW)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"allow", fmt.Sprintf("%d/tcp", shared.PortSSH)},
		Timeout: FirewallTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to allow SSH port: %w", err)
	}

	logger.Debug("SSH port allowed in firewall", zap.Int("port", shared.PortSSH))
	return nil
}

// logSSHRules displays current firewall rules related to SSH
func logSSHRules(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status", "numbered"},
		Capture: true,
		Timeout: FirewallTimeout,
	})
	if err != nil {
		logger.Debug("Failed to get UFW status", zap.Error(err))
		return
	}

	// Extract SSH-related rules
	lines := strings.Split(output, "\n")
	var sshRules []string
	for _, line := range lines {
		if strings.Contains(line, "22") || strings.Contains(line, "SSH") || strings.Contains(line, "ssh") {
			sshRules = append(sshRules, strings.TrimSpace(line))
		}
	}

	if len(sshRules) > 0 {
		logger.Info("Current SSH firewall rules", zap.Strings("rules", sshRules))
	}
}

// CheckFirewallStatus returns information about current firewall state
func CheckFirewallStatus(rc *eos_io.RuntimeContext) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status", "verbose"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get firewall status: %w", err)
	}

	return output, nil
}

// IsSSHAllowed checks if SSH port is allowed in the firewall
func IsSSHAllowed(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		logger.Debug("Failed to check UFW status", zap.Error(err))
		return false
	}

	// Check if SSH or port 22 is allowed
	return strings.Contains(output, "22") ||
		strings.Contains(strings.ToLower(output), "ssh")
}
