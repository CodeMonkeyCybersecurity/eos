// pkg/bootstrap/idempotent.go
//
// Idempotent bootstrap behavior that can safely run multiple times
// without causing errors or unintended side effects.

package bootstrap

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// IdempotentBootstrapResult represents the result of an idempotent bootstrap operation
type IdempotentBootstrapResult struct {
	AlreadyCompleted []string // Components that were already in desired state
	Executed         []string // Components that were installed/configured
	Skipped          []string // Components that were skipped
	Failed           []string // Components that failed
	Summary          string   // Overall summary
}

// PerformIdempotentBootstrap performs bootstrap in an idempotent manner
func PerformIdempotentBootstrap(rc *eos_io.RuntimeContext, opts *BootstrapOptions) (*IdempotentBootstrapResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting idempotent bootstrap")

	result := &IdempotentBootstrapResult{
		AlreadyCompleted: []string{},
		Executed:         []string{},
		Skipped:          []string{},
		Failed:           []string{},
	}

	// Define components to check/install
	components := []string{"vault", "consul", "nomad"}

	for _, component := range components {
		logger.Info("Checking component", zap.String("component", component))

		status := checkComponentIdempotency(rc, component)
		
		switch status.State {
		case IdempotentStateCompleted:
			logger.Info("Component already in desired state", 
				zap.String("component", component),
				zap.String("reason", status.Reason))
			result.AlreadyCompleted = append(result.AlreadyCompleted, component)

		case IdempotentStateNeedsUpdate:
			logger.Info("Component needs update", 
				zap.String("component", component),
				zap.String("reason", status.Reason))
			
			if err := performComponentUpdate(rc, component, status); err != nil {
				logger.Error("Failed to update component", 
					zap.String("component", component),
					zap.Error(err))
				result.Failed = append(result.Failed, component)
			} else {
				result.Executed = append(result.Executed, component)
			}

		case IdempotentStateNeedsInstall:
			logger.Info("Component needs installation", 
				zap.String("component", component),
				zap.String("reason", status.Reason))
			
			if err := performComponentInstall(rc, component, opts); err != nil {
				logger.Error("Failed to install component", 
					zap.String("component", component),
					zap.Error(err))
				result.Failed = append(result.Failed, component)
			} else {
				result.Executed = append(result.Executed, component)
			}

		case IdempotentStateSkipped:
			logger.Info("Component skipped", 
				zap.String("component", component),
				zap.String("reason", status.Reason))
			result.Skipped = append(result.Skipped, component)

		case IdempotentStateError:
			logger.Error("Component check failed", 
				zap.String("component", component),
				zap.String("reason", status.Reason))
			result.Failed = append(result.Failed, component)
		}
	}

	// Generate summary
	result.Summary = generateIdempotentSummary(result)
	
	logger.Info("Idempotent bootstrap completed", 
		zap.String("summary", result.Summary),
		zap.Int("completed", len(result.AlreadyCompleted)),
		zap.Int("executed", len(result.Executed)),
		zap.Int("skipped", len(result.Skipped)),
		zap.Int("failed", len(result.Failed)))

	return result, nil
}

// IdempotentState represents the state of a component for idempotent operations
type IdempotentState string

const (
	IdempotentStateCompleted    IdempotentState = "completed"     // Already in desired state
	IdempotentStateNeedsUpdate  IdempotentState = "needs_update"  // Needs configuration update
	IdempotentStateNeedsInstall IdempotentState = "needs_install" // Needs installation
	IdempotentStateSkipped      IdempotentState = "skipped"       // Intentionally skipped
	IdempotentStateError        IdempotentState = "error"         // Error checking state
)

// ComponentIdempotencyStatus represents the idempotency status of a component
type ComponentIdempotencyStatus struct {
	Component string
	State     IdempotentState
	Reason    string
	Version   string
	ConfigOK  bool
	ServiceOK bool
}

// checkComponentIdempotency checks if a component is in the desired state
func checkComponentIdempotency(rc *eos_io.RuntimeContext, component string) ComponentIdempotencyStatus {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking component idempotency", zap.String("component", component))

	status := ComponentIdempotencyStatus{
		Component: component,
	}

	// Check if component is installed
	if !isComponentInstalledIdempotent(rc, component) {
		status.State = IdempotentStateNeedsInstall
		status.Reason = "Component not installed"
		return status
	}

	// Check if service is running (for service components)
	if isServiceComponent(component) {
		if !isServiceRunning(rc, component) {
			status.State = IdempotentStateNeedsUpdate
			status.Reason = "Service not running"
			return status
		}
		status.ServiceOK = true
	}

	// Check if configuration is correct
	if !isConfigurationCorrect(rc, component) {
		status.State = IdempotentStateNeedsUpdate
		status.Reason = "Configuration needs update"
		status.ConfigOK = false
		return status
	}
	status.ConfigOK = true

	// Check if service is healthy
	if isServiceComponent(component) && !isServiceHealthy(rc, component) {
		status.State = IdempotentStateNeedsUpdate
		status.Reason = "Service unhealthy"
		return status
	}

	// All checks passed
	status.State = IdempotentStateCompleted
	status.Reason = "Component in desired state"
	status.Version = getComponentVersion(rc, component)
	
	return status
}

// isComponentInstalledIdempotent checks if a component is installed
func isComponentInstalledIdempotent(rc *eos_io.RuntimeContext, component string) bool {
	switch component {
	case "vault":
		return checkBinaryExists(rc, "vault")
	case "consul":
		return checkBinaryExists(rc, "consul")
	case "nomad":
		return checkBinaryExists(rc, "nomad")
	default:
		return false
	}
}

// checkPackageInstalled checks if a package is installed via dpkg
func checkPackageInstalled(rc *eos_io.RuntimeContext, packageName string) bool {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", packageName},
		Capture: true,
	})
	
	return err == nil && strings.Contains(output, "ii")
}

// checkBinaryExists checks if a binary exists in PATH
func checkBinaryExists(rc *eos_io.RuntimeContext, binaryName string) bool {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{binaryName},
		Capture: true,
	})
	
	return err == nil
}

// isServiceComponent checks if a component is a systemd service
func isServiceComponent(component string) bool {
	serviceComponents := []string{"vault", "consul", "nomad"}
	for _, service := range serviceComponents {
		if component == service {
			return true
		}
	}
	return false
}

// isConfigurationCorrect checks if component configuration is correct
func isConfigurationCorrect(rc *eos_io.RuntimeContext, component string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	switch component {

	case "vault":
		return checkVaultConfiguration(rc)
	case "consul":
		return checkConsulConfiguration(rc)
	case "nomad":
		return checkNomadConfiguration(rc)
	default:
		logger.Debug("No configuration check defined for component", zap.String("component", component))
		return true
	}
}



// checkVaultConfiguration checks if Vault configuration is correct
func checkVaultConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check if Vault config exists
	configPath := "/etc/vault/vault.hcl"
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", configPath},
		Capture: false,
	})
	
	return err == nil
}

// checkConsulConfiguration checks if Consul configuration is correct
func checkConsulConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check if Consul config exists
	configPath := "/etc/consul/consul.hcl"
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", configPath},
		Capture: false,
	})
	
	return err == nil
}

// checkNomadConfiguration checks if Nomad configuration is correct
func checkNomadConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check if Nomad config exists
	configPath := "/etc/nomad/nomad.hcl"
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", configPath},
		Capture: false,
	})
	
	return err == nil
}

// isServiceHealthy checks if a service is healthy
func isServiceHealthy(rc *eos_io.RuntimeContext, component string) bool {
	switch component {
	case "vault":
		return checkVaultHealth(rc)
	case "consul":
		return checkConsulHealth(rc)
	case "nomad":
		return checkNomadHealth(rc)
	default:
		return true
	}
}

// getComponentVersion gets the version of a component
func getComponentVersion(rc *eos_io.RuntimeContext, component string) string {
	switch component {
	case "vault":
		return getVaultVersion(rc)
	case "consul":
		return getConsulVersion(rc)
	case "nomad":
		return getNomadVersion(rc)
	default:
		return ""
	}
}

// performComponentInstall installs a component
func performComponentInstall(rc *eos_io.RuntimeContext, component string, _ *BootstrapOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing component", zap.String("component", component))

	switch component {

	case "vault":
		return installVault(rc)
	case "consul":
		return installConsul(rc)
	case "nomad":
		return installNomad(rc)
	default:
		return fmt.Errorf("unknown component: %s", component)
	}
}

// performComponentUpdate updates a component
func performComponentUpdate(rc *eos_io.RuntimeContext, component string, status ComponentIdempotencyStatus) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating component", 
		zap.String("component", component),
		zap.String("reason", status.Reason))

	switch component {

	case "vault":
		return updateVault(rc)
	case "consul":
		return updateConsul(rc)
	case "nomad":
		return updateNomad(rc)
	default:
		return fmt.Errorf("unknown component: %s", component)
	}
}

func installVault(rc *eos_io.RuntimeContext) error {
	// This would call the actual Vault installation
	return fmt.Errorf("vault installation not yet integrated")
}

func installConsul(rc *eos_io.RuntimeContext) error {
	// This would call the actual Consul installation
	return fmt.Errorf("consul installation not yet integrated")
}

func installNomad(rc *eos_io.RuntimeContext) error {
	// This would call the actual Nomad installation
	return fmt.Errorf("nomad installation not yet integrated")
}

func updateVault(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf("vault update not yet implemented")
}

func updateConsul(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf("consul update not yet implemented")
}

func updateNomad(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf("nomad update not yet implemented")
}

// generateIdempotentSummary generates a summary of the idempotent bootstrap
func generateIdempotentSummary(result *IdempotentBootstrapResult) string {
	total := len(result.AlreadyCompleted) + len(result.Executed) + len(result.Skipped) + len(result.Failed)
	
	if total == 0 {
		return "No components processed"
	}
	
	if len(result.Failed) > 0 {
		return fmt.Sprintf("Completed with %d failures out of %d components", len(result.Failed), total)
	}
	
	if len(result.Executed) == 0 {
		return "All components already in desired state"
	}
	
	return fmt.Sprintf("Successfully processed %d components (%d already complete, %d updated)", 
		total, len(result.AlreadyCompleted), len(result.Executed))
}

// PrintIdempotentResult prints a formatted result of idempotent bootstrap
func PrintIdempotentResult(rc *eos_io.RuntimeContext, result *IdempotentBootstrapResult) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("╔══════════════════════════════════════╗")
	logger.Info("║      Idempotent Bootstrap Results    ║")
	logger.Info("╚══════════════════════════════════════╝")
	
	logger.Info("Summary: " + result.Summary)
	logger.Info("")
	
	if len(result.AlreadyCompleted) > 0 {
		logger.Info("✅ Already in desired state:")
		for _, component := range result.AlreadyCompleted {
			logger.Info("   • " + component)
		}
		logger.Info("")
	}
	
	if len(result.Executed) > 0 {
		logger.Info("🔧 Updated/Installed:")
		for _, component := range result.Executed {
			logger.Info("   • " + component)
		}
		logger.Info("")
	}
	
	if len(result.Skipped) > 0 {
		logger.Info("⏭️  Skipped:")
		for _, component := range result.Skipped {
			logger.Info("   • " + component)
		}
		logger.Info("")
	}
	
	if len(result.Failed) > 0 {
		logger.Error("❌ Failed:")
		for _, component := range result.Failed {
			logger.Error("   • " + component)
		}
		logger.Info("")
	}
}