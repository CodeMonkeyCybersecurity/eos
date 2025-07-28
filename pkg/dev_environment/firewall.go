package dev_environment

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureFirewall sets up firewall rules for code-server access
func ConfigureFirewall(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring firewall for code-server access")

	// Check if ufw is installed and enabled
	ufwStatus, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		logger.Warn("UFW not installed or accessible, skipping firewall configuration", zap.Error(err))
		return nil
	}

	// Check if UFW is active
	if !strings.Contains(ufwStatus, "Status: active") {
		logger.Info("UFW is not active, enabling it")
		
		// First, ensure SSH is allowed
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ufw",
			Args:    []string{"allow", "22/tcp"},
			Timeout: 10 * time.Second,
		}); err != nil {
			logger.Warn("Failed to allow SSH", zap.Error(err))
		}

		// Enable UFW non-interactively
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ufw",
			Args:    []string{"--force", "enable"},
			Timeout: 10 * time.Second,
		}); err != nil {
			return fmt.Errorf("failed to enable UFW: %w", err)
		}
	}

	// Define network ranges to allow
	networks := []string{
		TailscaleNetwork, // Tailscale
		ConsulNetwork,    // Consul (if exists)
		LocalNetwork,     // Local LAN
		"172.16.0.0/12",  // Additional private networks
		"10.0.0.0/8",     // Additional private networks
	}

	// Add user-specified networks
	networks = append(networks, config.AllowedNetworks...)

	// Add firewall rules for each network
	for _, network := range networks {
		logger.Info("Adding firewall rule", 
			zap.String("network", network),
			zap.Int("port", CodeServerPort))

		rule := fmt.Sprintf("allow from %s to any port %d", network, CodeServerPort)
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ufw",
			Args:    strings.Fields(rule),
			Timeout: 10 * time.Second,
		}); err != nil {
			logger.Warn("Failed to add firewall rule",
				zap.String("network", network),
				zap.Error(err))
			// Continue with other rules
		}
	}

	// Also add a general rule for the port (commented out by default for security)
	logger.Info("Note: General access to port 8080 is restricted to specific networks for security")

	// Reload firewall rules
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"reload"},
		Timeout: 10 * time.Second,
	}); err != nil {
		logger.Warn("Failed to reload firewall rules", zap.Error(err))
	}

	// Show current rules for code-server port
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status", "numbered"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err == nil {
		// Filter for port 8080 rules
		lines := strings.Split(output, "\n")
		relevantRules := []string{}
		for _, line := range lines {
			if strings.Contains(line, fmt.Sprintf("%d", CodeServerPort)) {
				relevantRules = append(relevantRules, line)
			}
		}
		
		if len(relevantRules) > 0 {
			logger.Info("Firewall rules added for code-server",
				zap.Strings("rules", relevantRules))
		}
	}

	return nil
}

// VerifyInstallation checks that everything is working correctly
func VerifyInstallation(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying development environment installation")

	issues := []string{}

	// Check code-server service
	serviceName := fmt.Sprintf("code-server@%s", config.User)
	if status, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil || strings.TrimSpace(status) != "active" {
		issues = append(issues, fmt.Sprintf("code-server service is not active (status: %s)", strings.TrimSpace(status)))
	}

	// Check if port is listening
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", CodeServerPort)},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil || !strings.Contains(output, fmt.Sprintf(":%d", CodeServerPort)) {
		issues = append(issues, fmt.Sprintf("Port %d is not listening", CodeServerPort))
	}

	// Check GitHub CLI
	if !config.SkipGH {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{"gh"},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err != nil {
			issues = append(issues, "GitHub CLI not found in PATH")
		}
	}

	// Check firewall rules
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		if !strings.Contains(output, fmt.Sprintf("%d", CodeServerPort)) {
			issues = append(issues, fmt.Sprintf("No firewall rules found for port %d", CodeServerPort))
		}
	}

	// Report issues
	if len(issues) > 0 {
		logger.Warn("Verification found issues",
			zap.Strings("issues", issues))
		
		fmt.Println("\n⚠️  Verification found some issues:")
		for _, issue := range issues {
			fmt.Printf("   - %s\n", issue)
		}
		fmt.Println("\nThese issues may not prevent code-server from working.")
		return fmt.Errorf("verification found %d issues", len(issues))
	}

	logger.Info("All verifications passed")
	return nil
}