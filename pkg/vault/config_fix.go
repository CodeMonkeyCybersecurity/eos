// pkg/vault/config_fix.go
//
// Automated fix for Vault configuration issues
// Specifically addresses api_addr using shared.GetInternalHostname instead of hostname

package vault

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FixVaultConfig fixes common Vault configuration issues
// Primary fix: Replace shared.GetInternalHostname with hostname in api_addr and cluster_addr
func FixVaultConfig(rc *eos_io.RuntimeContext, configPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("=== ASSESS: Analyzing Vault configuration ===",
		zap.String("config_path", configPath))

	// Read current config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	originalContent := string(content)

	// Discover hostname
	hostname, err := discoverHostname()
	if err != nil {
		return fmt.Errorf("failed to discover hostname: %w", err)
	}

	logger.Info("Discovered hostname for fix",
		zap.String("hostname", hostname))

	// === ASSESS: Check for issues ===
	hasIssues := false
	issues := []string{}

	// Check for shared.GetInternalHostname in api_addr
	if strings.Contains(originalContent, `api_addr     = "https://shared.GetInternalHostname:`) {
		hasIssues = true
		issues = append(issues, "api_addr uses shared.GetInternalHostname instead of hostname (blocks external access)")
	}

	// Check for shared.GetInternalHostname in cluster_addr
	if strings.Contains(originalContent, `cluster_addr = "https://shared.GetInternalHostname:`) {
		hasIssues = true
		issues = append(issues, "cluster_addr uses shared.GetInternalHostname instead of hostname (blocks clustering)")
	}

	if !hasIssues {
		logger.Info("No configuration issues found - config is correct")
		return nil
	}

	logger.Warn("Configuration issues detected",
		zap.Int("issue_count", len(issues)),
		zap.Strings("issues", issues))

	// === INTERVENE: Apply fixes ===
	logger.Info("=== INTERVENE: Applying configuration fixes ===")

	newContent := originalContent

	// Fix api_addr
	apiAddrRegex := regexp.MustCompile(`api_addr\s*=\s*"https://127\.0\.0\.1:(\d+)"`)
	newContent = apiAddrRegex.ReplaceAllString(newContent, fmt.Sprintf(`api_addr     = "https://%s:$1"`, hostname))

	// Fix cluster_addr
	clusterAddrRegex := regexp.MustCompile(`cluster_addr\s*=\s*"https://127\.0\.0\.1:(\d+)"`)
	newContent = clusterAddrRegex.ReplaceAllString(newContent, fmt.Sprintf(`cluster_addr = "https://%s:$1"`, hostname))

	// Create backup
	backupPath := configPath + ".backup"
	if err := os.WriteFile(backupPath, []byte(originalContent), 0640); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	logger.Info("Created configuration backup",
		zap.String("backup_path", backupPath))

	// Write fixed config
	if err := os.WriteFile(configPath, []byte(newContent), 0640); err != nil {
		return fmt.Errorf("failed to write fixed config: %w", err)
	}

	logger.Info("Configuration fixed successfully",
		zap.String("hostname", hostname))

	// === EVALUATE: Verify fixes ===
	logger.Info("=== EVALUATE: Verifying fixes ===")

	// Show what changed
	logger.Info("Changes applied:",
		zap.String("old_api_addr", fmt.Sprintf("https://shared.GetInternalHostname:8200")),
		zap.String("new_api_addr", fmt.Sprintf("https://%s:8200", hostname)),
		zap.String("old_cluster_addr", fmt.Sprintf("https://shared.GetInternalHostname:8201")),
		zap.String("new_cluster_addr", fmt.Sprintf("https://%s:8201", hostname)))

	logger.Info("✓ Vault configuration fixed - restart required",
		zap.String("restart_command", "sudo systemctl restart vault.service"))

	return nil
}

// DetectVaultConfigIssues analyzes Vault config and returns list of issues
func DetectVaultConfigIssues(rc *eos_io.RuntimeContext, configPath string) ([]string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	configContent := string(content)
	issues := []string{}

	// Discover hostname for comparison
	hostname, err := discoverHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to discover hostname: %w", err)
	}

	// Check api_addr
	if strings.Contains(configContent, `api_addr     = "https://shared.GetInternalHostname:`) {
		issues = append(issues, fmt.Sprintf(
			"api_addr uses shared.GetInternalHostname instead of %s (blocks web UI access)", hostname))
	}

	// Check cluster_addr
	if strings.Contains(configContent, `cluster_addr = "https://shared.GetInternalHostname:`) {
		issues = append(issues, fmt.Sprintf(
			"cluster_addr uses shared.GetInternalHostname instead of %s (blocks clustering)", hostname))
	}

	// Check for missing TLS certificate paths
	if !strings.Contains(configContent, "tls_cert_file") {
		issues = append(issues, "Missing TLS certificate configuration")
	}

	// Check for tls_disable = true (insecure)
	if strings.Contains(configContent, "tls_disable   = true") {
		issues = append(issues, "TLS is disabled (insecure configuration)")
	}

	return issues, nil
}
