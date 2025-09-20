// pkg/bootstrap/check.go
//
// EOS Bootstrap System - Machine Preparation and Validation
//
// The EOS bootstrap system ensures machines are properly prepared before deploying
// services. This prevents common errors like "Salt state files not found" and
// ensures a consistent, secure foundation for all deployments.
//
// Why Bootstrap is Required:
// Without proper bootstrapping, users encounter:
// - Salt can't find state files
// - API credentials aren't configured  
// - Services fail to deploy
// - Inconsistent system states
// - Security vulnerabilities
//
// Bootstrap provides:
// - Configuration management (SaltStack)
// - Secure API communication
// - Proper file system structure
// - Network verification
// - Security baseline
//
// Bootstrap Architecture:
// Every service deployment command checks bootstrap status using RequireBootstrap().
// The system validates:
// - SaltStack Installation: Configuration management system
// - Salt API Configuration: REST API for remote management
// - File Roots Setup: Paths to EOS state files
// - Network Configuration: Basic connectivity
// - Security Configuration: Firewall and basics
//
// IMPLEMENTATION STATUS (September 20, 2025):
//
// ✅ COMPLETED COMPONENTS:
//
// Core Storage Operations Framework:
// - Storage Analyzer (pkg/storage/analyzer/) - Real-time analysis and monitoring
// - Threshold Management (pkg/storage/threshold/) - Progressive action system
// - Filesystem Detection (pkg/storage/filesystem/) - Smart filesystem recommendations
// - Emergency Recovery (pkg/storage/emergency/) - Automated space recovery
// - Environment Detection (pkg/environment/) - Scale-aware configuration
//
// Bootstrap Integration:
// - Cluster Detection (pkg/bootstrap/detector.go) - Single vs multi-node detection
// - Node Registration (pkg/bootstrap/registration.go) - New node joining workflow
// - Role Assignment (pkg/bootstrap/roles.go) - Dynamic role calculation
// - Storage Integration (pkg/bootstrap/storage_integration.go) - Automatic deployment
// - Enhanced Bootstrap Commands (cmd/bootstrap/bootstrap_enhanced.go) - Complete CLI integration
//
// HashiCorp Stack Migration:
// - Following the successful SaltStack to HashiCorp migration, bootstrap now integrates
//   with Consul for service discovery, Nomad for orchestration, and Vault for secrets
// - Administrator escalation patterns implemented for system-level operations
// - Clear architectural boundaries between application and system operations
//
// MIGRATION CONTEXT:
// The bootstrap system has been updated to work with the new HashiCorp stack while
// maintaining backward compatibility. System-level operations now properly escalate
// to administrator intervention, while application services use HashiCorp orchestration.
// - Security Configuration: Firewall and basics
//
// User Experience:
// When bootstrap is missing, users get clear guidance:
//   Error: System not bootstrapped
//   Run: eos bootstrap
//   This will: Install SaltStack, configure API, set up file roots
//
// Usage:
//   status, err := bootstrap.CheckBootstrap(rc)
//   if err != nil || !status.Bootstrapped {
//       return bootstrap.RequireBootstrap(rc)
//   }
//
// Integration:
// Bootstrap integrates with all EOS create commands to ensure proper system
// preparation before service deployment. It provides the foundation for the
// EOS infrastructure compiler pattern.
package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapStatus represents the bootstrap state of the machine
type BootstrapStatus struct {
	Bootstrapped        bool
	SaltInstalled       bool
	SaltAPIConfigured   bool
	FileRootsConfigured bool
	NetworkConfigured   bool
	SecurityConfigured  bool
	Timestamp           time.Time
	Version             string
	Issues              []string
}

// CheckBootstrap performs a comprehensive bootstrap check
func CheckBootstrap(rc *eos_io.RuntimeContext) (*BootstrapStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Performing bootstrap status check")

	status := &BootstrapStatus{
		Timestamp: time.Now(),
		Issues:    []string{},
	}

	// Check 1: Salt Installation
	if installed, version := checkSaltInstalled(rc); installed {
		status.SaltInstalled = true
		status.Version = version
		logger.Debug("Salt is installed", zap.String("version", version))
	} else {
		status.Issues = append(status.Issues, "SaltStack is not installed")
	}

	// Check 2: Salt API Configuration
	if apiConfigured := checkSaltAPIConfigured(rc); apiConfigured {
		status.SaltAPIConfigured = true
		logger.Debug("Salt API is configured")
	} else {
		status.Issues = append(status.Issues, "Salt API is not configured")
	}

	// Check 3: File Roots Configuration
	if fileRootsOK := checkFileRootsConfigured(rc); fileRootsOK {
		status.FileRootsConfigured = true
		logger.Debug("File roots are properly configured")
	} else {
		status.Issues = append(status.Issues, "Salt file_roots are not properly configured")
	}

	// Check 4: Network Configuration (basic checks)
	if networkOK := checkNetworkConfiguration(rc); networkOK {
		status.NetworkConfigured = true
		logger.Debug("Network configuration looks good")
	} else {
		status.Issues = append(status.Issues, "Network configuration may need attention")
	}

	// Check 5: Security Configuration (basic checks)
	if securityOK := checkSecurityConfiguration(rc); securityOK {
		status.SecurityConfigured = true
		logger.Debug("Basic security configuration is in place")
	} else {
		status.Issues = append(status.Issues, "Security configuration needs attention")
	}

	// Use state-based validation instead of marker files
	// Check if all required phases are complete
	complete, missingPhases := IsBootstrapComplete(rc)
	if complete {
		status.Bootstrapped = true
		logger.Debug("Bootstrap complete - all required phases validated")
	} else {
		status.Bootstrapped = false
		logger.Debug("Bootstrap incomplete", zap.Strings("missing_phases", missingPhases))
		for _, phase := range missingPhases {
			status.Issues = append(status.Issues, fmt.Sprintf("%s phase not completed", phase))
		}
	}

	return status, nil
}

// RequireBootstrap checks if the system is bootstrapped and returns an error if not
func RequireBootstrap(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Use state validation to check if bootstrap is complete
	complete, missingPhases := IsBootstrapComplete(rc)
	
	if complete {
		logger.Debug("Bootstrap validation passed - all required components are running")
		return nil
	}
	
	// System is not fully bootstrapped
	logger.Error("System bootstrap incomplete",
		zap.Strings("missing_phases", missingPhases))
	
	// Provide helpful error message
	logger.Info("terminal prompt: ❌ ERROR: System bootstrap is incomplete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: The following components are missing or not running:")
	
	for _, phase := range missingPhases {
		var issue string
		switch phase {
		case "salt":
			issue = "SaltStack is not installed or not running"
		case "salt-api":
			issue = "Salt API service is not configured or not running"
		default:
			issue = fmt.Sprintf("%s is not configured", phase)
		}
		logger.Info(fmt.Sprintf("terminal prompt:   ✗ %s", issue))
	}
	
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To complete the bootstrap, run:")
	logger.Info("terminal prompt:   sudo eos bootstrap")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: The bootstrap will automatically:")
	logger.Info("terminal prompt:   • Detect what's missing")
	logger.Info("terminal prompt:   • Complete only the necessary steps")
	logger.Info("terminal prompt:   • Verify all services are running")
	
	return fmt.Errorf("bootstrap incomplete - missing: %s", strings.Join(missingPhases, ", "))
}

// FIXME: [P4] Code duplication - this function is duplicated in state_validator.go
// checkSaltInstalled checks if Salt is installed
func checkSaltInstalled(rc *eos_io.RuntimeContext) (bool, string) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return false, ""
	}

	// Parse version from output
	version := "unknown"
	if output != "" {
		// Output format: "salt-call 3006.3"
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			version = parts[1]
		}
	}

	return true, version
}

// checkSaltAPIConfigured checks if Salt API is configured and accessible
func checkSaltAPIConfigured(rc *eos_io.RuntimeContext) bool {
	// Check if EOS Salt API service is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "eos-salt-api"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil || strings.TrimSpace(output) != "active" {
		// Also check for the standard salt-api service as fallback
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "salt-api"},
			Capture: true,
			Timeout: 5 * time.Second,
		})
		
		if err != nil || strings.TrimSpace(output) != "active" {
			return false
		}
	}

	// Check if API endpoint responds on port 5000 (EOS Salt API)
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:5000/health"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	httpCode := strings.TrimSpace(output)
	if httpCode == "200" {
		return true
	}

	// Fallback: Check standard Salt API on port 8000
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://localhost:8000"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	httpCode = strings.TrimSpace(output)
	return httpCode == "401" || httpCode == "200" // 401 is expected without auth
}

// checkFileRootsConfigured verifies Salt file_roots are properly set up
func checkFileRootsConfigured(_ *eos_io.RuntimeContext) bool {
	// Check if required directories exist
	requiredDirs := []string{
		"/srv/salt",
		"/opt/eos/salt/states",
	}

	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return false
		}
	}

	// Check if symlinks are correct
	expectedLink := "/srv/salt/hashicorp"
	if target, err := os.Readlink(expectedLink); err != nil || target != "/opt/eos/salt/states/hashicorp" {
		return false
	}

	return true
}

// checkNetworkConfiguration performs basic network checks
func checkNetworkConfiguration(rc *eos_io.RuntimeContext) bool {
	// Basic check - can we resolve DNS?
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"hosts", "github.com"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	return err == nil && output != ""
}

// checkSecurityConfiguration performs basic security checks
func checkSecurityConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check if UFW is installed (common Ubuntu firewall)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"ufw"},
		Capture: true,
		Timeout: 2 * time.Second,
	})

	// For now, just check if firewall tool exists
	// More comprehensive checks can be added
	return err == nil
}

// MarkBootstrapped is deprecated - we use state-based validation now
// This function is kept for backward compatibility but does nothing
func MarkBootstrapped(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("MarkBootstrapped called but ignored - using state-based validation")
	return nil
}