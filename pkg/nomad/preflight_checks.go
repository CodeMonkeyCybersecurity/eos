package nomad

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PreflightCheckResult contains the results of preflight checks
type PreflightCheckResult struct {
	ConsulInstalled  bool
	ConsulRunning    bool
	VaultInstalled   bool
	VaultRunning     bool
	DockerInstalled  bool
	DockerRunning    bool
	HasRootPrivilege bool
	PortsAvailable   []int
	PortsInUse       []int
	Issues           []string
	Warnings         []string
	CanProceed       bool
}

// RunPreflightChecks performs comprehensive checks before Nomad installation
func RunPreflightChecks(rc *eos_io.RuntimeContext) (*PreflightCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Nomad installation preflight checks")

	result := &PreflightCheckResult{
		CanProceed:     true,
		PortsAvailable: []int{},
		PortsInUse:     []int{},
		Issues:         []string{},
		Warnings:       []string{},
	}

	// Check root privileges
	if os.Geteuid() != 0 {
		result.HasRootPrivilege = false
		result.Issues = append(result.Issues, "Root privileges required for installation")
		result.CanProceed = false
	} else {
		result.HasRootPrivilege = true
		logger.Info("✓ Running with root privileges")
	}

	// Check for Consul (required dependency)
	checkConsulDependency(rc, result)

	// Check for Vault (optional but recommended)
	checkVaultDependency(rc, result)

	// Check for Docker (optional runtime)
	checkDockerDependency(rc, result)

	// Check required ports
	checkPortAvailability(rc, result)

	// Check if Nomad is already installed
	checkExistingInstallation(rc, result)

	// Determine if we can proceed
	if result.ConsulInstalled && !result.ConsulRunning {
		result.Issues = append(result.Issues, "Consul is installed but not running")
		result.CanProceed = false
	}

	if !result.ConsulInstalled {
		result.Issues = append(result.Issues, "Consul is required but not installed")
		result.CanProceed = false
	}

	return result, nil
}

func checkConsulDependency(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Consul binary exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"consul"},
		Capture: true,
	})

	if err != nil {
		result.ConsulInstalled = false
		logger.Info("✗ Consul not installed (required dependency)")
		return
	}

	result.ConsulInstalled = true
	logger.Info("✓ Consul is installed")

	// Check if Consul is running
	status, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})

	if err == nil && strings.TrimSpace(status) == "active" {
		result.ConsulRunning = true
		logger.Info("✓ Consul service is active")
	} else {
		result.ConsulRunning = false
		logger.Info("✗ Consul service is not running")
	}
}

func checkVaultDependency(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Vault binary exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"vault"},
		Capture: true,
	})

	if err != nil {
		result.VaultInstalled = false
		result.Warnings = append(result.Warnings, "Vault not installed (recommended for secret management)")
		logger.Info("⚠ Vault not installed (optional but recommended)")
		return
	}

	result.VaultInstalled = true
	logger.Info("✓ Vault is installed")

	// Check if Vault is running
	status, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})

	if err == nil && strings.TrimSpace(status) == "active" {
		result.VaultRunning = true
		logger.Info("✓ Vault service is active")
	} else {
		result.VaultRunning = false
		logger.Info("⚠ Vault service is not running")
	}
}

func checkDockerDependency(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Docker binary exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"docker"},
		Capture: true,
	})

	if err != nil {
		result.DockerInstalled = false
		result.Warnings = append(result.Warnings, "Docker not installed (optional container runtime)")
		logger.Info("⚠ Docker not installed (optional)")
		return
	}

	result.DockerInstalled = true
	logger.Info("✓ Docker is installed")

	// Check if Docker is running
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	})

	if err == nil {
		result.DockerRunning = true
		logger.Info("✓ Docker daemon is running")
	} else {
		result.DockerRunning = false
		result.Warnings = append(result.Warnings, "Docker daemon is not running")
		logger.Info("⚠ Docker daemon is not running")
	}
}

func checkPortAvailability(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking port availability")

	// Nomad required ports
	requiredPorts := map[int]string{
		4646: "Nomad HTTP API",
		4647: "Nomad RPC",
		4648: "Nomad Serf WAN",
	}

	for port, service := range requiredPorts {
		// Check if port is in use
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ss",
			Args:    []string{"-tlnp"},
			Capture: true,
		})

		if err == nil && strings.Contains(output, fmt.Sprintf(":%d", port)) {
			result.PortsInUse = append(result.PortsInUse, port)
			result.Issues = append(result.Issues, fmt.Sprintf("Port %d (%s) is already in use", port, service))
			result.CanProceed = false
			logger.Info("✗ Port in use", zap.Int("port", port), zap.String("service", service))
		} else {
			result.PortsAvailable = append(result.PortsAvailable, port)
			logger.Info("✓ Port available", zap.Int("port", port), zap.String("service", service))
		}
	}
}

func checkExistingInstallation(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Nomad is already installed
	nomadPath, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
	})

	if err == nil && strings.TrimSpace(nomadPath) != "" {
		result.Warnings = append(result.Warnings, "Nomad is already installed at: "+strings.TrimSpace(nomadPath))
		logger.Info("⚠ Nomad already installed", zap.String("path", strings.TrimSpace(nomadPath)))

		// Check version
		version, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"version"},
			Capture: true,
		})

		if err == nil {
			logger.Info("Existing Nomad version", zap.String("version", strings.Split(version, "\n")[0]))
		}
	}
}

// HandleMissingDependencies interactively handles missing dependencies
func HandleMissingDependencies(rc *eos_io.RuntimeContext, result *PreflightCheckResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	if result.ConsulInstalled && result.ConsulRunning {
		return nil // All good
	}

	if !result.ConsulInstalled {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Consul is required for Nomad but is not installed.")

		consent, err := eos_io.PromptForDependency(rc, "HashiCorp Consul", "service discovery and networking", "Nomad")
		if err != nil {
			return fmt.Errorf("failed to get user consent: %w", err)
		}

		if !consent {
			return eos_err.NewUserError("Nomad installation cancelled - Consul is required")
		}

		// Install Consul
		logger.Info("Installing Consul...")

		eosPath, err := os.Executable()
		if err != nil {
			eosPath = "/usr/local/bin/eos"
		}

		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: eosPath,
			Args:    []string{"create", "consul"},
			Capture: false, // Show output to user
		})

		if err != nil {
			logger.Error("Failed to install Consul", zap.Error(err))

			// Ask if they want to continue anyway
			continueAnyway, _ := eos_io.PromptToContinueDespiteErrors(rc, 1, "Consul installation")
			if !continueAnyway {
				return eos_err.NewUserError("Nomad installation cancelled - Consul installation failed")
			}
		} else {
			logger.Info("✓ Consul installed successfully")
		}
	} else if !result.ConsulRunning {
		// Consul installed but not running
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Consul is installed but not running.")

		consent, err := eos_io.PromptForServiceAction(rc, "consul", "start")
		if err != nil {
			return fmt.Errorf("failed to get user consent: %w", err)
		}

		if consent {
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"start", "consul"},
			})

			if err != nil {
				logger.Error("Failed to start Consul", zap.Error(err))
				result.Warnings = append(result.Warnings, "Failed to start Consul service")
			} else {
				logger.Info("✓ Consul service started")
			}
		}
	}

	return nil
}

// DisplayPreflightSummary shows a summary of preflight check results
func DisplayPreflightSummary(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ╔════════════════════════════════════════════════════════════════╗")
	logger.Info("terminal prompt: ║              NOMAD PREFLIGHT CHECK SUMMARY                     ║")
	logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	logger.Info("terminal prompt: ")

	logger.Info("terminal prompt: DEPENDENCIES:")
	logger.Info("terminal prompt:", zap.String("status", fmt.Sprintf("  • Consul:  Installed: %v, Running: %v %s",
		result.ConsulInstalled, result.ConsulRunning, getStatusIcon(result.ConsulInstalled && result.ConsulRunning))))
	logger.Info("terminal prompt:", zap.String("status", fmt.Sprintf("  • Vault:   Installed: %v, Running: %v %s",
		result.VaultInstalled, result.VaultRunning, getStatusIcon(result.VaultInstalled && result.VaultRunning))))
	logger.Info("terminal prompt:", zap.String("status", fmt.Sprintf("  • Docker:  Installed: %v, Running: %v %s",
		result.DockerInstalled, result.DockerRunning, getStatusIcon(result.DockerInstalled && result.DockerRunning))))

	if len(result.Issues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  CRITICAL ISSUES:")
		for _, issue := range result.Issues {
			logger.Info("terminal prompt:", zap.String("issue", fmt.Sprintf("  • %s", issue)))
		}
	}

	if len(result.Warnings) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: WARNINGS:")
		for _, warning := range result.Warnings {
			logger.Info("terminal prompt:", zap.String("warning", fmt.Sprintf("  • %s", warning)))
		}
	}

	logger.Info("terminal prompt: ")
	if result.CanProceed {
		logger.Info("terminal prompt:  Preflight checks passed - ready to install Nomad")
	} else {
		logger.Info("terminal prompt:  Preflight checks failed - issues must be resolved")
	}
}

func getStatusIcon(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}
