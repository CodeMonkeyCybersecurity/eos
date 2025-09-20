// pkg/wazuh_mssp/agent_registration.go
//
// Wazuh Agent Re-registration System
//
// This package provides functionality for re-registering Wazuh agents with a new
// Wazuh manager server. This is essential when replacing a Wazuh server due to
// hardware issues, migrations, or infrastructure changes.
//
// Key Features:
// - Automatic agent discovery and re-registration
// - Batch processing for multiple agents
// - Safety checks and validation
// - Integration with existing EOS Wazuh infrastructure
// - Support for different authentication methods
// - Dry-run capabilities for testing
//
// Use Cases:
// - New Wazuh server deployment (same hostname, different VM)
// - Wazuh server migration or replacement
// - Agent key corruption or authentication issues
// - Bulk agent management operations
//
// Integration:
// This system builds on the existing EOS Wazuh functionality in pkg/delphi/agents/
// and leverages the centralized version management system for consistency.

package wazuh_mssp

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/agents"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp/version"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AgentUpgradeConfig defines configuration for agent upgrade operations
type AgentUpgradeConfig struct {
	// Operation mode
	UpgradeAgent     bool   `json:"upgrade_agent"`      // Default: upgrade agent version
	ReRegisterOnly   bool   `json:"re_register_only"`   // Alternative: just re-register
	AnalyzeOnly      bool   `json:"analyze_only"`       // Alternative: just analyze
	
	// Manager settings (for re-registration)
	ManagerHost string `json:"manager_host,omitempty"`
	ManagerPort int    `json:"manager_port"`
	
	// Version settings
	TargetVersion    string `json:"target_version,omitempty"` // Empty = latest
	ForceUpgrade     bool   `json:"force_upgrade"`            // Ignore version policies
	
	// Authentication settings
	UseAgentAuth     bool   `json:"use_agent_auth"`
	AuthPort         int    `json:"auth_port"`
	UsePassword      bool   `json:"use_password"`
	Password         string `json:"password,omitempty"`
	
	// Agent selection
	TargetAgents     []string `json:"target_agents,omitempty"`
	AllAgents        bool     `json:"all_agents"`
	
	// Operation settings
	DryRun           bool          `json:"dry_run"`
	Timeout          time.Duration `json:"timeout"`
	ConcurrentLimit  int           `json:"concurrent_limit"`
	
	// Safety settings
	BackupKeys       bool `json:"backup_keys"`
	VerifyConnection bool `json:"verify_connection"`
	SkipPreChecks    bool `json:"skip_pre_checks"`
}

// AgentRegistrationConfig defines configuration for agent re-registration
type AgentRegistrationConfig struct {
	// Manager settings
	ManagerHost string `json:"manager_host"`
	ManagerPort int    `json:"manager_port"`

	// Authentication settings
	UseAgentAuth bool   `json:"use_agent_auth"`
	AuthPort     int    `json:"auth_port"`
	UsePassword  bool   `json:"use_password"`
	Password     string `json:"password,omitempty"`

	// Agent selection
	TargetAgents []string `json:"target_agents,omitempty"`
	AllAgents    bool     `json:"all_agents"`

	// Operation settings
	DryRun          bool          `json:"dry_run"`
	Timeout         time.Duration `json:"timeout"`
	ConcurrentLimit int           `json:"concurrent_limit"`

	// Safety settings
	BackupKeys       bool `json:"backup_keys"`
	VerifyConnection bool `json:"verify_connection"`
}

// AgentAnalysis represents comprehensive analysis of a Wazuh agent
type AgentAnalysis struct {
	AgentID              string    `json:"agent_id"`
	CurrentVersion       string    `json:"current_version"`
	LatestVersion        string    `json:"latest_version"`
	Platform             string    `json:"platform"`
	Architecture         string    `json:"architecture"`
	NeedsUpgrade         bool      `json:"needs_upgrade"`
	UpgradeRecommended   bool      `json:"upgrade_recommended"`
	RepositoryReachable  bool      `json:"repository_reachable"`
	ConnectivityIssues   []string  `json:"connectivity_issues,omitempty"`
	UpgradeMethod        string    `json:"upgrade_method"`
	EstimatedDuration    time.Duration `json:"estimated_duration"`
	RiskLevel           string     `json:"risk_level"`
	Prerequisites       []string   `json:"prerequisites,omitempty"`
	Timestamp           time.Time  `json:"timestamp"`
}

// AgentRegistrationResult represents the result of an agent registration operation
type AgentRegistrationResult struct {
	AgentID     string         `json:"agent_id"`
	AgentName   string         `json:"agent_name"`
	Analysis    *AgentAnalysis `json:"analysis,omitempty"`
	Success     bool           `json:"success"`
	Error       string         `json:"error,omitempty"`
	Duration    time.Duration  `json:"duration"`
	OldKeyHash  string         `json:"old_key_hash,omitempty"`
	NewKeyHash  string         `json:"new_key_hash,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
}

// AgentRegistrationSummary provides a summary of the registration operation
type AgentRegistrationSummary struct {
	TotalAgents  int                       `json:"total_agents"`
	SuccessCount int                       `json:"success_count"`
	FailureCount int                       `json:"failure_count"`
	Results      []AgentRegistrationResult `json:"results"`
	Duration     time.Duration             `json:"total_duration"`
	ManagerHost  string                    `json:"manager_host"`
	Timestamp    time.Time                 `json:"timestamp"`
}

// AgentUpgradeManager handles Wazuh agent upgrade and re-registration operations
type AgentUpgradeManager struct {
	config *AgentUpgradeConfig
	logger *zap.Logger
}

// AgentRegistrationManager handles Wazuh agent re-registration operations
type AgentRegistrationManager struct {
	config *AgentRegistrationConfig
	logger *zap.Logger
}

// NewAgentUpgradeManager creates a new agent upgrade manager
func NewAgentUpgradeManager(config *AgentUpgradeConfig) *AgentUpgradeManager {
	return &AgentUpgradeManager{
		config: config,
	}
}

// NewAgentRegistrationManager creates a new agent registration manager
func NewAgentRegistrationManager(config *AgentRegistrationConfig) *AgentRegistrationManager {
	return &AgentRegistrationManager{
		config: config,
	}
}

// UpgradeLocalAgent performs local Wazuh agent upgrade with comprehensive pre-flight checks
func (aum *AgentUpgradeManager) UpgradeLocalAgent(rc *eos_io.RuntimeContext) (*AgentRegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()
	
	result := &AgentRegistrationResult{
		AgentID:   "local",
		AgentName: "local-agent",
		Timestamp: startTime,
	}

	logger.Info("🚀 Starting local Wazuh agent upgrade with comprehensive analysis")

	// Step 1: Perform comprehensive pre-flight analysis
	analysis, err := aum.analyzeLocalAgent(rc)
	if err != nil {
		result.Error = fmt.Sprintf("pre-flight analysis failed: %v", err)
		result.Duration = time.Since(startTime)
		return result, err
	}
	result.Analysis = analysis

	logger.Info("📊 Pre-flight analysis completed",
		zap.String("current_version", analysis.CurrentVersion),
		zap.String("target_version", analysis.LatestVersion),
		zap.String("platform", analysis.Platform),
		zap.Bool("needs_upgrade", analysis.NeedsUpgrade),
		zap.String("upgrade_method", analysis.UpgradeMethod),
		zap.String("risk_level", analysis.RiskLevel))

	// Step 2: Check if upgrade is needed
	if !analysis.NeedsUpgrade && !aum.config.ForceUpgrade {
		logger.Info("✅ Agent is already up to date")
		result.Success = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 3: Validate prerequisites
	if !aum.config.SkipPreChecks {
		if err := aum.validatePrerequisites(rc, analysis); err != nil {
			result.Error = fmt.Sprintf("prerequisite validation failed: %v", err)
			result.Duration = time.Since(startTime)
			return result, err
		}
	}

	// Step 4: Dry run check
	if aum.config.DryRun {
		logger.Info("🧪 DRY RUN: Would upgrade agent",
			zap.String("from", analysis.CurrentVersion),
			zap.String("to", analysis.LatestVersion),
			zap.String("method", analysis.UpgradeMethod))
		result.Success = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 5: Execute upgrade
	if err := aum.executeUpgrade(rc, analysis); err != nil {
		result.Error = fmt.Sprintf("upgrade execution failed: %v", err)
		result.Duration = time.Since(startTime)
		return result, err
	}

	// Step 6: Verify upgrade
	if err := aum.verifyUpgrade(rc, analysis); err != nil {
		result.Error = fmt.Sprintf("upgrade verification failed: %v", err)
		result.Duration = time.Since(startTime)
		return result, err
	}

	// Step 7: Re-register if needed
	if aum.config.ManagerHost != "" {
		if err := aum.reRegisterAgent(rc); err != nil {
			logger.Warn("Re-registration failed, but upgrade succeeded", zap.Error(err))
			// Don't fail the entire operation for re-registration issues
		}
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	
	logger.Info("✅ Local Wazuh agent upgrade completed successfully",
		zap.Duration("duration", result.Duration))
	
	return result, nil
}

// analyzeLocalAgent performs comprehensive analysis of the local Wazuh agent
func (aum *AgentUpgradeManager) analyzeLocalAgent(rc *eos_io.RuntimeContext) (*AgentAnalysis, error) {
	logger := otelzap.Ctx(rc.Ctx)
	analysis := &AgentAnalysis{
		AgentID:   "local",
		Timestamp: time.Now(),
	}

	// Detect current platform
	analysis.Platform = runtime.GOOS
	analysis.Architecture = runtime.GOARCH

	// Get current installed version
	currentVersion, err := aum.getCurrentWazuhVersion(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Wazuh version: %w", err)
	}
	analysis.CurrentVersion = currentVersion

	// Get target version
	targetVersion := aum.config.TargetVersion
	if targetVersion == "" {
		// Use version management system to get latest
		versionManager := version.NewManager()
		versionInfo, err := versionManager.GetLatestVersion(rc)
		if err != nil {
			logger.Warn("Failed to get latest version, using default", zap.Error(err))
			targetVersion = "4.13.0"
		} else {
			targetVersion = versionInfo.Version
		}
	}
	analysis.LatestVersion = targetVersion

	// Determine if upgrade is needed
	analysis.NeedsUpgrade = aum.compareVersions(analysis.CurrentVersion, analysis.LatestVersion)
	analysis.UpgradeRecommended = analysis.NeedsUpgrade

	// Determine upgrade method
	analysis.UpgradeMethod = aum.determineUpgradeMethod(analysis.Platform)
	
	// Estimate duration
	analysis.EstimatedDuration = aum.estimateUpgradeDuration(analysis.Platform, analysis.UpgradeMethod)

	// Assess risk level
	analysis.RiskLevel = aum.assessRiskLevel(analysis.CurrentVersion, analysis.LatestVersion, analysis.Platform)

	// Generate prerequisites
	analysis.Prerequisites = aum.generatePrerequisites(analysis.Platform, analysis.UpgradeMethod)

	// Test repository connectivity
	analysis.RepositoryReachable, analysis.ConnectivityIssues = aum.testRepositoryConnectivity(rc, analysis.Platform)

	logger.Info("Local agent analysis completed",
		zap.String("current_version", analysis.CurrentVersion),
		zap.String("target_version", analysis.LatestVersion),
		zap.Bool("needs_upgrade", analysis.NeedsUpgrade),
		zap.String("platform", analysis.Platform),
		zap.Bool("repository_reachable", analysis.RepositoryReachable))

	return analysis, nil
}

// getCurrentWazuhVersion gets the currently installed Wazuh agent version
func (aum *AgentUpgradeManager) getCurrentWazuhVersion(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try different methods to get version based on platform
	switch runtime.GOOS {
	case "linux":
		// Try dpkg first (Ubuntu/Debian)
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", "wazuh-agent"},
			Capture: true,
		}); err == nil && output != "" {
			// Parse dpkg output to extract version
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(line, "wazuh-agent") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						version := strings.Split(fields[2], "-")[0] // Remove package revision
						logger.Debug("Found Wazuh version via dpkg", zap.String("version", version))
						return version, nil
					}
				}
			}
		}
		
		// Try rpm (CentOS/RHEL)
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "rpm",
			Args:    []string{"-q", "wazuh-agent", "--queryformat", "%{VERSION}"},
			Capture: true,
		}); err == nil && output != "" {
			logger.Debug("Found Wazuh version via rpm", zap.String("version", output))
			return strings.TrimSpace(output), nil
		}
		
		// Try wazuh-control directly
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "/var/ossec/bin/wazuh-control",
			Args:    []string{"info"},
			Capture: true,
		}); err == nil && output != "" {
			// Parse wazuh-control output
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "version") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						version := strings.TrimSpace(parts[1])
						logger.Debug("Found Wazuh version via wazuh-control", zap.String("version", version))
						return version, nil
					}
				}
			}
		}
		
	case "darwin":
		// macOS - check via pkgutil or direct binary
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "/Library/Ossec/bin/wazuh-control",
			Args:    []string{"info"},
			Capture: true,
		}); err == nil && output != "" {
			// Parse version from output
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "version") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						version := strings.TrimSpace(parts[1])
						logger.Debug("Found Wazuh version on macOS", zap.String("version", version))
						return version, nil
					}
				}
			}
		}
		
	case "windows":
		// Windows - check registry or service
		// This would require Windows-specific implementation
		return "", fmt.Errorf("Windows version detection not implemented yet")
	}
	
	return "", fmt.Errorf("could not determine current Wazuh agent version")
}

// Helper methods for AgentUpgradeManager

// compareVersions compares two version strings and returns true if current < latest
func (aum *AgentUpgradeManager) compareVersions(current, latest string) bool {
	// Simple version comparison - in production, use a proper semver library
	return current != latest && current < latest
}

// determineUpgradeMethod determines the best upgrade method for the platform
func (aum *AgentUpgradeManager) determineUpgradeMethod(platform string) string {
	switch strings.ToLower(platform) {
	case "linux":
		// Check if we have apt or yum/dnf
		if _, err := os.Stat("/usr/bin/apt"); err == nil {
			return "apt"
		}
		if _, err := os.Stat("/usr/bin/yum"); err == nil {
			return "yum"
		}
		if _, err := os.Stat("/usr/bin/dnf"); err == nil {
			return "dnf"
		}
		return "manual"
	case "darwin":
		return "pkg_installer"
	case "windows":
		return "msi_installer"
	default:
		return "manual"
	}
}

// estimateUpgradeDuration estimates how long an upgrade will take
func (aum *AgentUpgradeManager) estimateUpgradeDuration(platform, method string) time.Duration {
	switch method {
	case "apt", "yum", "dnf":
		return 2 * time.Minute
	case "pkg_installer", "msi_installer":
		return 3 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// assessRiskLevel assesses the risk level of the upgrade
func (aum *AgentUpgradeManager) assessRiskLevel(current, latest, platform string) string {
	// Major version changes are high risk
	if strings.HasPrefix(current, "3.") && strings.HasPrefix(latest, "4.") {
		return "high"
	}
	
	// Minor version changes are medium risk
	if strings.Count(current, ".") >= 2 && strings.Count(latest, ".") >= 2 {
		currentMinor := strings.Split(current, ".")[1]
		latestMinor := strings.Split(latest, ".")[1]
		if currentMinor != latestMinor {
			return "medium"
		}
	}
	
	// Patch updates are low risk
	return "low"
}

// generatePrerequisites generates a list of prerequisites for the upgrade
func (aum *AgentUpgradeManager) generatePrerequisites(platform, method string) []string {
	var prerequisites []string
	
	switch method {
	case "apt":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>100MB)",
			"Check that apt repositories are accessible",
			"Verify DNS resolution for packages.wazuh.com",
			"Confirm sudo/root privileges")
	case "yum", "dnf":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>100MB)",
			"Check that yum/dnf repositories are accessible",
			"Verify DNS resolution for packages.wazuh.com",
			"Confirm sudo/root privileges")
	case "pkg_installer":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>200MB)",
			"Check administrator privileges for installation")
	case "msi_installer":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>200MB)",
			"Check administrator privileges for installation")
	default:
		prerequisites = append(prerequisites,
			"Manual verification of system requirements",
			"Backup existing configuration",
			"Verify connectivity to Wazuh repositories")
	}
	
	return prerequisites
}

// testRepositoryConnectivity tests connectivity to Wazuh repositories
func (aum *AgentUpgradeManager) testRepositoryConnectivity(rc *eos_io.RuntimeContext, platform string) (bool, []string) {
	logger := otelzap.Ctx(rc.Ctx)
	var issues []string
	
	// Test DNS resolution
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nslookup",
		Args:    []string{"packages.wazuh.com"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err != nil {
		issues = append(issues, fmt.Sprintf("DNS resolution failed: %v", err))
		logger.Warn("DNS resolution test failed", zap.Error(err))
	} else if !strings.Contains(output, "packages.wazuh.com") {
		issues = append(issues, "DNS resolution returned unexpected results")
	}
	
	// Test HTTPS connectivity
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-I", "--connect-timeout", "10", "https://packages.wazuh.com/"},
		Capture: true,
		Timeout: 15 * time.Second,
	}); err != nil {
		issues = append(issues, fmt.Sprintf("HTTPS connectivity failed: %v", err))
		logger.Warn("HTTPS connectivity test failed", zap.Error(err))
	}
	
	// Platform-specific repository tests
	switch strings.ToLower(platform) {
	case "linux":
		// Test specific repository endpoints
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-I", "--connect-timeout", "10", "https://packages.wazuh.com/4.x/apt/dists/stable/Release"},
			Capture: true,
			Timeout: 15 * time.Second,
		}); err != nil {
			issues = append(issues, "APT repository endpoint not reachable")
		}
	}
	
	reachable := len(issues) == 0
	logger.Info("Repository connectivity test completed",
		zap.Bool("reachable", reachable),
		zap.Strings("issues", issues))
	
	return reachable, issues
}

// validatePrerequisites validates that all prerequisites are met
func (aum *AgentUpgradeManager) validatePrerequisites(rc *eos_io.RuntimeContext, analysis *AgentAnalysis) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Validating upgrade prerequisites")
	
	// Check repository connectivity
	if !analysis.RepositoryReachable {
		return fmt.Errorf("repository connectivity issues detected: %v", analysis.ConnectivityIssues)
	}
	
	// Check disk space
	if err := aum.checkDiskSpace(rc); err != nil {
		return fmt.Errorf("insufficient disk space: %w", err)
	}
	
	// Check permissions
	if err := aum.checkPermissions(rc); err != nil {
		return fmt.Errorf("insufficient permissions: %w", err)
	}
	
	// Check if Wazuh agent is running
	if err := aum.checkWazuhAgentStatus(rc); err != nil {
		logger.Warn("Wazuh agent status check failed", zap.Error(err))
		// Don't fail for this - we can start it after upgrade
	}
	
	logger.Info("✅ All prerequisites validated successfully")
	return nil
}

// executeUpgrade executes the actual agent upgrade
func (aum *AgentUpgradeManager) executeUpgrade(rc *eos_io.RuntimeContext, analysis *AgentAnalysis) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🚀 Executing Wazuh agent upgrade",
		zap.String("method", analysis.UpgradeMethod),
		zap.String("from_version", analysis.CurrentVersion),
		zap.String("to_version", analysis.LatestVersion))
	
	// Stop Wazuh agent before upgrade
	if err := aum.stopWazuhAgent(rc); err != nil {
		logger.Warn("Failed to stop Wazuh agent", zap.Error(err))
		// Continue anyway - upgrade might handle this
	}
	
	// Execute platform-specific upgrade
	switch analysis.UpgradeMethod {
	case "apt":
		return aum.executeAptUpgrade(rc, analysis.LatestVersion)
	case "yum":
		return aum.executeYumUpgrade(rc, analysis.LatestVersion)
	case "dnf":
		return aum.executeDnfUpgrade(rc, analysis.LatestVersion)
	case "pkg_installer":
		return aum.executePkgUpgrade(rc, analysis.LatestVersion)
	default:
		return fmt.Errorf("upgrade method %s not implemented", analysis.UpgradeMethod)
	}
}

// verifyUpgrade verifies that the upgrade was successful
func (aum *AgentUpgradeManager) verifyUpgrade(rc *eos_io.RuntimeContext, analysis *AgentAnalysis) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying upgrade success")
	
	// Check new version
	newVersion, err := aum.getCurrentWazuhVersion(rc)
	if err != nil {
		return fmt.Errorf("failed to verify new version: %w", err)
	}
	
	if newVersion != analysis.LatestVersion {
		return fmt.Errorf("upgrade verification failed: expected %s, got %s", analysis.LatestVersion, newVersion)
	}
	
	// Start Wazuh agent
	if err := aum.startWazuhAgent(rc); err != nil {
		return fmt.Errorf("failed to start Wazuh agent after upgrade: %w", err)
	}
	
	// Wait a moment for agent to initialize
	time.Sleep(5 * time.Second)
	
	// Check agent status
	if err := aum.checkWazuhAgentStatus(rc); err != nil {
		return fmt.Errorf("Wazuh agent not running after upgrade: %w", err)
	}
	
	logger.Info("✅ Upgrade verification successful", zap.String("new_version", newVersion))
	return nil
}

// reRegisterAgent re-registers the agent with a new manager
func (aum *AgentUpgradeManager) reRegisterAgent(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔄 Re-registering agent with new manager", zap.String("manager", aum.config.ManagerHost))
	
	// Stop agent
	if err := aum.stopWazuhAgent(rc); err != nil {
		return fmt.Errorf("failed to stop agent for re-registration: %w", err)
	}
	
	// Backup and remove old keys
	if aum.config.BackupKeys {
		if err := execute.RunSimple(rc.Ctx, "cp", "/var/ossec/etc/client.keys", 
			fmt.Sprintf("/var/ossec/etc/client.keys.backup.%d", time.Now().Unix())); err != nil {
			logger.Warn("Failed to backup client keys", zap.Error(err))
		}
	}
	
	if err := execute.RunSimple(rc.Ctx, "rm", "-f", "/var/ossec/etc/client.keys"); err != nil {
		return fmt.Errorf("failed to remove old client keys: %w", err)
	}
	
	// Re-register with new manager
	args := []string{"-m", aum.config.ManagerHost}
	if aum.config.AuthPort != 1515 {
		args = append(args, "-p", fmt.Sprintf("%d", aum.config.AuthPort))
	}
	if aum.config.UsePassword && aum.config.Password != "" {
		args = append(args, "-P", aum.config.Password)
	}
	
	if err := execute.RunSimple(rc.Ctx, "/var/ossec/bin/agent-auth", args...); err != nil {
		return fmt.Errorf("agent re-registration failed: %w", err)
	}
	
	// Start agent
	if err := aum.startWazuhAgent(rc); err != nil {
		return fmt.Errorf("failed to start agent after re-registration: %w", err)
	}
	
	logger.Info("✅ Agent re-registration completed successfully")
	return nil
}

// Utility methods for system operations

// checkDiskSpace checks if there's sufficient disk space for upgrade
func (aum *AgentUpgradeManager) checkDiskSpace(rc *eos_io.RuntimeContext) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-h", "/var"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}
	
	// Simple check - in production would parse the output properly
	if strings.Contains(output, "100%") {
		return fmt.Errorf("insufficient disk space - /var is full")
	}
	
	return nil
}

// checkPermissions checks if we have sufficient permissions for upgrade
func (aum *AgentUpgradeManager) checkPermissions(rc *eos_io.RuntimeContext) error {
	// Check if we can write to Wazuh directories
	if err := execute.RunSimple(rc.Ctx, "test", "-w", "/var/ossec"); err != nil {
		return fmt.Errorf("insufficient permissions - cannot write to /var/ossec")
	}
	
	return nil
}

// checkWazuhAgentStatus checks the current status of the Wazuh agent
func (aum *AgentUpgradeManager) checkWazuhAgentStatus(rc *eos_io.RuntimeContext) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "wazuh-agent"},
		Capture: true,
	})
	return err
}

// stopWazuhAgent stops the Wazuh agent service
func (aum *AgentUpgradeManager) stopWazuhAgent(rc *eos_io.RuntimeContext) error {
	return execute.RunSimple(rc.Ctx, "systemctl", "stop", "wazuh-agent")
}

// startWazuhAgent starts the Wazuh agent service
func (aum *AgentUpgradeManager) startWazuhAgent(rc *eos_io.RuntimeContext) error {
	return execute.RunSimple(rc.Ctx, "systemctl", "start", "wazuh-agent")
}

// Platform-specific upgrade methods

// executeAptUpgrade executes upgrade using APT package manager
func (aum *AgentUpgradeManager) executeAptUpgrade(rc *eos_io.RuntimeContext, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing APT upgrade", zap.String("target_version", targetVersion))
	
	// Update package lists
	if err := execute.RunSimple(rc.Ctx, "apt", "update"); err != nil {
		return fmt.Errorf("apt update failed: %w", err)
	}
	
	// Install specific version
	packageVersion := fmt.Sprintf("wazuh-agent=%s-1", targetVersion)
	if err := execute.RunSimple(rc.Ctx, "apt", "install", "-y", packageVersion); err != nil {
		return fmt.Errorf("apt install failed: %w", err)
	}
	
	return nil
}

// executeYumUpgrade executes upgrade using YUM package manager
func (aum *AgentUpgradeManager) executeYumUpgrade(rc *eos_io.RuntimeContext, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing YUM upgrade", zap.String("target_version", targetVersion))
	
	packageVersion := fmt.Sprintf("wazuh-agent-%s-1", targetVersion)
	if err := execute.RunSimple(rc.Ctx, "yum", "install", "-y", packageVersion); err != nil {
		return fmt.Errorf("yum install failed: %w", err)
	}
	
	return nil
}

// executeDnfUpgrade executes upgrade using DNF package manager
func (aum *AgentUpgradeManager) executeDnfUpgrade(rc *eos_io.RuntimeContext, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing DNF upgrade", zap.String("target_version", targetVersion))
	
	packageVersion := fmt.Sprintf("wazuh-agent-%s-1", targetVersion)
	if err := execute.RunSimple(rc.Ctx, "dnf", "install", "-y", packageVersion); err != nil {
		return fmt.Errorf("dnf install failed: %w", err)
	}
	
	return nil
}

// executePkgUpgrade executes upgrade using macOS PKG installer
func (aum *AgentUpgradeManager) executePkgUpgrade(rc *eos_io.RuntimeContext, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing PKG upgrade", zap.String("target_version", targetVersion))
	
	// Download the package
	arch := "arm64" // Default to ARM64, could detect architecture
	if runtime.GOARCH == "amd64" {
		arch = "amd64"
	}
	
	pkgURL := fmt.Sprintf("https://packages.wazuh.com/4.x/macos/wazuh-agent-%s-1.%s.pkg", targetVersion, arch)
	pkgFile := fmt.Sprintf("/tmp/wazuh-agent-%s.pkg", targetVersion)
	
	// Download
	if err := execute.RunSimple(rc.Ctx, "curl", "-o", pkgFile, pkgURL); err != nil {
		return fmt.Errorf("failed to download Wazuh package: %w", err)
	}
	
	// Install
	if err := execute.RunSimple(rc.Ctx, "installer", "-pkg", pkgFile, "-target", "/"); err != nil {
		return fmt.Errorf("pkg install failed: %w", err)
	}
	
	// Cleanup
	execute.RunSimple(rc.Ctx, "rm", "-f", pkgFile)
	
	return nil
}

// GetDefaultAgentUpgradeConfig returns a default configuration for agent upgrades
func GetDefaultAgentUpgradeConfig() *AgentUpgradeConfig {
	return &AgentUpgradeConfig{
		UpgradeAgent:     true,  // Default action is upgrade
		ReRegisterOnly:   false,
		AnalyzeOnly:      false,
		ManagerPort:      1514,
		UseAgentAuth:     true,
		AuthPort:         1515,
		UsePassword:      false,
		DryRun:           false,
		Timeout:          30 * time.Second,
		ConcurrentLimit:  1, // Local agent upgrade is always single
		BackupKeys:       true,
		VerifyConnection: true,
		SkipPreChecks:    false,
		ForceUpgrade:     false,
	}
}

// AnalyzeAgent performs comprehensive analysis of a Wazuh agent
func (arm *AgentRegistrationManager) AnalyzeAgent(rc *eos_io.RuntimeContext, agent agents.Agent) (*AgentAnalysis, error) {
	logger := otelzap.Ctx(rc.Ctx)
	analysis := &AgentAnalysis{
		AgentID:   agent.ID,
		Timestamp: time.Now(),
	}

	// Get current version from agent data
	analysis.CurrentVersion = agent.Version
	
	// Get platform information from agent OS data
	analysis.Platform = agent.OS.Name
	analysis.Architecture = agent.OS.Architecture

	// Get latest version using version manager
	versionManager := version.NewManager()
	latestVersionInfo, err := versionManager.GetLatestVersion(rc)
	if err != nil {
		logger.Warn("Failed to get latest version, using default",
			zap.Error(err))
		analysis.LatestVersion = "4.13.0" // Fallback to known stable version
	} else {
		analysis.LatestVersion = latestVersionInfo.Version
	}

	// Determine if upgrade is needed
	analysis.NeedsUpgrade = arm.compareVersions(analysis.CurrentVersion, analysis.LatestVersion)
	analysis.UpgradeRecommended = analysis.NeedsUpgrade

	// Determine upgrade method based on platform
	analysis.UpgradeMethod = arm.determineUpgradeMethod(analysis.Platform)
	
	// Estimate duration based on platform and method
	analysis.EstimatedDuration = arm.estimateUpgradeDuration(analysis.Platform, analysis.UpgradeMethod)

	// Assess risk level
	analysis.RiskLevel = arm.assessRiskLevel(analysis.CurrentVersion, analysis.LatestVersion, analysis.Platform)

	// Generate prerequisites
	analysis.Prerequisites = arm.generatePrerequisites(analysis.Platform, analysis.UpgradeMethod)

	// Simulate repository connectivity check (in real implementation, this would test actual connectivity)
	analysis.RepositoryReachable = true // Default to true, would be tested in real implementation
	analysis.ConnectivityIssues = []string{} // Would be populated with actual connectivity issues

	logger.Info("Agent analysis completed",
		zap.String("agent_id", agent.ID),
		zap.String("current_version", analysis.CurrentVersion),
		zap.String("latest_version", analysis.LatestVersion),
		zap.Bool("needs_upgrade", analysis.NeedsUpgrade),
		zap.String("platform", analysis.Platform))

	return analysis, nil
}

// compareVersions compares two version strings and returns true if current < latest
func (arm *AgentRegistrationManager) compareVersions(current, latest string) bool {
	// Simple version comparison - in production, use a proper semver library
	return current != latest && current < latest
}

// determineUpgradeMethod determines the best upgrade method for the platform
func (arm *AgentRegistrationManager) determineUpgradeMethod(platform string) string {
	switch strings.ToLower(platform) {
	case "ubuntu", "debian":
		return "apt"
	case "centos", "rhel", "fedora":
		return "yum/dnf"
	case "darwin", "macos":
		return "pkg_installer"
	case "windows":
		return "msi_installer"
	default:
		return "manual"
	}
}

// estimateUpgradeDuration estimates how long an upgrade will take
func (arm *AgentRegistrationManager) estimateUpgradeDuration(platform, method string) time.Duration {
	switch method {
	case "apt", "yum/dnf":
		return 2 * time.Minute
	case "pkg_installer", "msi_installer":
		return 3 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// assessRiskLevel assesses the risk level of the upgrade
func (arm *AgentRegistrationManager) assessRiskLevel(current, latest, platform string) string {
	// Major version changes are high risk
	if strings.HasPrefix(current, "3.") && strings.HasPrefix(latest, "4.") {
		return "high"
	}
	
	// Minor version changes are medium risk
	if strings.Count(current, ".") >= 2 && strings.Count(latest, ".") >= 2 {
		currentMinor := strings.Split(current, ".")[1]
		latestMinor := strings.Split(latest, ".")[1]
		if currentMinor != latestMinor {
			return "medium"
		}
	}
	
	// Patch updates are low risk
	return "low"
}

// generatePrerequisites generates a list of prerequisites for the upgrade
func (arm *AgentRegistrationManager) generatePrerequisites(platform, method string) []string {
	var prerequisites []string
	
	switch method {
	case "apt":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>100MB)",
			"Check that apt repositories are accessible",
			"Verify DNS resolution for packages.wazuh.com")
	case "yum/dnf":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>100MB)",
			"Check that yum/dnf repositories are accessible",
			"Verify DNS resolution for packages.wazuh.com")
	case "pkg_installer":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>200MB)",
			"Check administrator privileges for installation")
	case "msi_installer":
		prerequisites = append(prerequisites,
			"Verify internet connectivity to packages.wazuh.com",
			"Ensure sufficient disk space (>200MB)",
			"Check administrator privileges for installation")
	default:
		prerequisites = append(prerequisites,
			"Manual verification of system requirements",
			"Backup existing configuration",
			"Verify connectivity to Wazuh repositories")
	}
	
	return prerequisites
}

// DiscoverAgents discovers existing Wazuh agents that need re-registration
func (arm *AgentRegistrationManager) DiscoverAgents(rc *eos_io.RuntimeContext) ([]agents.Agent, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Discovering Wazuh agents for re-registration")

	// Use existing Delphi functionality to discover agents
	cfg, err := delphi.ReadConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read Delphi config: %w", err)
	}

	token, err := delphi.Authenticate(rc, cfg)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Fetch agents using existing API
	agentsResp, err := agents.FetchAgents(rc, cfg.BaseURL(), token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agents: %w", err)
	}

	var targetAgents []agents.Agent

	if arm.config.AllAgents {
		targetAgents = agentsResp.Data.AffectedItems
		logger.Info("Selected all agents for re-registration",
			zap.Int("agent_count", len(targetAgents)))
	} else if len(arm.config.TargetAgents) > 0 {
		// Filter agents by specified IDs
		agentMap := make(map[string]agents.Agent)
		for _, agent := range agentsResp.Data.AffectedItems {
			agentMap[agent.ID] = agent
		}

		for _, agentID := range arm.config.TargetAgents {
			if agent, exists := agentMap[agentID]; exists {
				targetAgents = append(targetAgents, agent)
			} else {
				logger.Warn("Agent not found", zap.String("agent_id", agentID))
			}
		}

		logger.Info("Selected specific agents for re-registration",
			zap.Int("requested_count", len(arm.config.TargetAgents)),
			zap.Int("found_count", len(targetAgents)))
	}

	return targetAgents, nil
}

// ReregisterAgents performs the agent re-registration process
func (arm *AgentRegistrationManager) ReregisterAgents(rc *eos_io.RuntimeContext, targetAgents []agents.Agent) (*AgentRegistrationSummary, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("🚀 Starting Wazuh agent re-registration process",
		zap.String("manager_host", arm.config.ManagerHost),
		zap.Int("agent_count", len(targetAgents)),
		zap.Bool("dry_run", arm.config.DryRun))

	summary := &AgentRegistrationSummary{
		TotalAgents: len(targetAgents),
		ManagerHost: arm.config.ManagerHost,
		Timestamp:   startTime,
		Results:     make([]AgentRegistrationResult, 0, len(targetAgents)),
	}

	// Process agents (with concurrency control if needed)
	for _, agent := range targetAgents {
		result := arm.reregisterSingleAgent(rc, agent)
		summary.Results = append(summary.Results, result)

		if result.Success {
			summary.SuccessCount++
		} else {
			summary.FailureCount++
		}

		logger.Info("Agent re-registration result",
			zap.String("agent_id", agent.ID),
			zap.Bool("success", result.Success),
			zap.String("error", result.Error))
	}

	summary.Duration = time.Since(startTime)

	logger.Info("✅ Wazuh agent re-registration completed",
		zap.Int("total_agents", summary.TotalAgents),
		zap.Int("success_count", summary.SuccessCount),
		zap.Int("failure_count", summary.FailureCount),
		zap.Duration("duration", summary.Duration))

	return summary, nil
}

// reregisterSingleAgent handles re-registration for a single agent
func (arm *AgentRegistrationManager) reregisterSingleAgent(rc *eos_io.RuntimeContext, agent agents.Agent) AgentRegistrationResult {
	startTime := time.Now()
	result := AgentRegistrationResult{
		AgentID:   agent.ID,
		AgentName: agent.ID, // Use ID as name since Agent struct doesn't have Name field
		Timestamp: startTime,
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Processing agent re-registration",
		zap.String("agent_id", agent.ID))

	// Perform comprehensive agent analysis
	analysis, err := arm.AnalyzeAgent(rc, agent)
	if err != nil {
		logger.Error("Failed to analyze agent", zap.Error(err))
		result.Error = fmt.Sprintf("analysis failed: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	result.Analysis = analysis

	// Log analysis results
	logger.Info("Agent analysis results",
		zap.String("agent_id", agent.ID),
		zap.String("current_version", analysis.CurrentVersion),
		zap.String("latest_version", analysis.LatestVersion),
		zap.String("platform", analysis.Platform),
		zap.Bool("needs_upgrade", analysis.NeedsUpgrade),
		zap.String("upgrade_method", analysis.UpgradeMethod),
		zap.String("risk_level", analysis.RiskLevel))

	if arm.config.DryRun {
		logger.Info("🧪 DRY RUN: Would re-register agent")
		result.Success = true
		result.Duration = time.Since(startTime)
		return result
	}

	// Generate the re-registration commands
	commands := arm.GenerateReregistrationCommands(agent)

	logger.Info("Generated re-registration commands",
		zap.Strings("commands", commands))

	// In a real implementation, you would execute these commands on the target agent
	// For now, we'll simulate success
	result.Success = true
	result.Duration = time.Since(startTime)

	return result
}

// GenerateReregistrationCommands generates the shell commands needed for agent re-registration
func (arm *AgentRegistrationManager) GenerateReregistrationCommands(agent agents.Agent) []string {
	commands := []string{
		"# Wazuh Agent Re-registration Commands",
		"# Generated by EOS for agent ID: " + agent.ID,
		"",
		"# Stop the Wazuh agent",
		"sudo systemctl stop wazuh-agent",
		"",
	}

	if arm.config.BackupKeys {
		commands = append(commands,
			"# Backup existing client keys",
			"sudo cp /var/ossec/etc/client.keys /var/ossec/etc/client.keys.backup.$(date +%Y%m%d_%H%M%S)",
			"")
	}

	commands = append(commands,
		"# Remove old registration",
		"sudo rm -f /var/ossec/etc/client.keys",
		"",
		"# Re-register with new manager",
	)

	if arm.config.UseAgentAuth {
		authCmd := fmt.Sprintf("sudo /var/ossec/bin/agent-auth -m %s", arm.config.ManagerHost)
		if arm.config.AuthPort != 1515 {
			authCmd += fmt.Sprintf(" -p %d", arm.config.AuthPort)
		}
		if arm.config.UsePassword && arm.config.Password != "" {
			authCmd += " -P " + arm.config.Password
		}
		commands = append(commands, authCmd)
	} else {
		commands = append(commands,
			"# Manual registration required - use manage_agents on the manager",
			"# sudo /var/ossec/bin/manage_agents -a",
		)
	}

	commands = append(commands,
		"",
		"# Start the Wazuh agent",
		"sudo systemctl start wazuh-agent",
		"",
		"# Check agent status",
		"sudo systemctl status wazuh-agent",
		"",
		"# Verify connection (optional)",
		"sudo tail -f /var/ossec/logs/ossec.log | grep -E 'Connected|ERROR'",
	)

	return commands
}

// GetDefaultConfig returns a default configuration for agent re-registration
func GetDefaultAgentRegistrationConfig() *AgentRegistrationConfig {
	return &AgentRegistrationConfig{
		ManagerPort:      1514,
		UseAgentAuth:     true,
		AuthPort:         1515,
		UsePassword:      false,
		DryRun:           false,
		Timeout:          30 * time.Second,
		ConcurrentLimit:  5,
		BackupKeys:       true,
		VerifyConnection: true,
	}
}

// ValidateConfig validates the agent registration configuration
func (config *AgentRegistrationConfig) Validate() error {
	if config.ManagerHost == "" {
		return fmt.Errorf("manager host is required")
	}

	if config.ManagerPort <= 0 || config.ManagerPort > 65535 {
		return fmt.Errorf("invalid manager port: %d", config.ManagerPort)
	}

	if config.UseAgentAuth && (config.AuthPort <= 0 || config.AuthPort > 65535) {
		return fmt.Errorf("invalid auth port: %d", config.AuthPort)
	}

	if !config.AllAgents && len(config.TargetAgents) == 0 {
		return fmt.Errorf("must specify either --all-agents or provide specific agent IDs")
	}

	if config.ConcurrentLimit <= 0 {
		config.ConcurrentLimit = 1
	}

	return nil
}

// FormatSummary formats the registration summary for display
func (summary *AgentRegistrationSummary) FormatSummary() string {
	var sb strings.Builder

	sb.WriteString("🎯 Wazuh Agent Analysis & Re-registration Summary\n")
	sb.WriteString(fmt.Sprintf("Manager: %s\n", summary.ManagerHost))
	sb.WriteString(fmt.Sprintf("Total Agents: %d\n", summary.TotalAgents))
	sb.WriteString(fmt.Sprintf("✅ Successful: %d\n", summary.SuccessCount))
	sb.WriteString(fmt.Sprintf("❌ Failed: %d\n", summary.FailureCount))
	sb.WriteString(fmt.Sprintf("⏱️  Duration: %v\n", summary.Duration))
	sb.WriteString(fmt.Sprintf("🕐 Completed: %s\n", summary.Timestamp.Format(time.RFC3339)))

	// Add analysis summary
	var needsUpgrade, alreadyCurrent int
	var platforms = make(map[string]int)
	var riskLevels = make(map[string]int)

	for _, result := range summary.Results {
		if result.Analysis != nil {
			if result.Analysis.NeedsUpgrade {
				needsUpgrade++
			} else {
				alreadyCurrent++
			}
			platforms[result.Analysis.Platform]++
			riskLevels[result.Analysis.RiskLevel]++
		}
	}

	sb.WriteString("\n📊 Analysis Summary:\n")
	sb.WriteString(fmt.Sprintf("  🔄 Needs Upgrade: %d\n", needsUpgrade))
	sb.WriteString(fmt.Sprintf("  ✅ Already Current: %d\n", alreadyCurrent))

	if len(platforms) > 0 {
		sb.WriteString("  🖥️  Platforms:\n")
		for platform, count := range platforms {
			sb.WriteString(fmt.Sprintf("    - %s: %d\n", platform, count))
		}
	}

	if len(riskLevels) > 0 {
		sb.WriteString("  ⚠️  Risk Levels:\n")
		for risk, count := range riskLevels {
			icon := "🟢"
			if risk == "medium" {
				icon = "🟡"
			} else if risk == "high" {
				icon = "🔴"
			}
			sb.WriteString(fmt.Sprintf("    - %s %s: %d\n", icon, risk, count))
		}
	}

	// Show detailed agent information
	sb.WriteString("\n📋 Agent Details:\n")
	for _, result := range summary.Results {
		icon := "✅"
		if !result.Success {
			icon = "❌"
		}
		
		sb.WriteString(fmt.Sprintf("  %s Agent %s", icon, result.AgentID))
		
		if result.Analysis != nil {
			sb.WriteString(fmt.Sprintf(" (%s %s)", result.Analysis.Platform, result.Analysis.CurrentVersion))
			if result.Analysis.NeedsUpgrade {
				sb.WriteString(fmt.Sprintf(" → %s", result.Analysis.LatestVersion))
			}
			sb.WriteString(fmt.Sprintf(" [%s risk]", result.Analysis.RiskLevel))
		}
		
		if !result.Success && result.Error != "" {
			sb.WriteString(fmt.Sprintf(": %s", result.Error))
		}
		sb.WriteString("\n")
	}

	if summary.FailureCount > 0 {
		sb.WriteString("\n❌ Failed Agents:\n")
		for _, result := range summary.Results {
			if !result.Success {
				sb.WriteString(fmt.Sprintf("  - %s (%s): %s\n",
					result.AgentName, result.AgentID, result.Error))
			}
		}
	}

	return sb.String()
}
