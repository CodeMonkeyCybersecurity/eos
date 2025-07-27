// pkg/bootstrap/state_validator.go
//
// State-based validation for bootstrap phases instead of relying on marker files

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseValidator checks if a bootstrap phase is actually complete
type PhaseValidator func(rc *eos_io.RuntimeContext) (bool, error)

// PhaseValidators maps phase names to their validation functions
var PhaseValidators map[string]PhaseValidator

func init() {
	PhaseValidators = map[string]PhaseValidator{
		"salt":      validateSaltPhase,
		"salt-api":  validateSaltAPIPhase,
		"storage":   validateStoragePhase,
		"tailscale": validateTailscalePhase,
		"osquery":   validateOSQueryPhase,
		"hardening": validateHardeningPhase,
	}
}

// ValidatePhaseCompletion checks if a phase is actually completed by examining system state
func ValidatePhaseCompletion(rc *eos_io.RuntimeContext, phaseName string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	validator, exists := PhaseValidators[phaseName]
	if !exists {
		logger.Debug("No validator for phase, assuming not complete", zap.String("phase", phaseName))
		return false
	}
	
	complete, err := validator(rc)
	if err != nil {
		logger.Debug("Phase validation error", 
			zap.String("phase", phaseName),
			zap.Error(err))
		return false
	}
	
	logger.Debug("Phase validation result",
		zap.String("phase", phaseName),
		zap.Bool("complete", complete))
	
	return complete
}

// validateSaltPhase checks if Salt is properly installed and configured
func validateSaltPhase(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating Salt installation")
	
	// Check if Salt is installed
	installed, version := checkSaltInstalled(rc)
	if !installed {
		logger.Debug("Salt not installed")
		return false, nil
	}
	
	logger.Debug("Salt installed", zap.String("version", version))
	
	// Check if file roots are configured
	if !checkFileRootsConfigured(rc) {
		logger.Debug("Salt file roots not properly configured")
		return false, nil
	}
	
	// Check Salt configuration directly instead of using CheckBootstrap to avoid circular dependency
	// Verify Salt configuration files exist
	saltConfigFiles := []string{
		"/etc/salt/minion.d/99-masterless.conf",
		"/etc/salt/minion.d/99-local.conf", 
		"/etc/salt/minion.d/99-cluster.conf",
		"/etc/salt/master.d/99-eos.conf",
	}
	
	configExists := false
	for _, configFile := range saltConfigFiles {
		if _, err := os.Stat(configFile); err == nil {
			configExists = true
			logger.Debug("Found Salt configuration", zap.String("config", configFile))
			break
		}
	}
	
	if !configExists {
		logger.Debug("No Salt configuration files found")
		return false, nil
	}
	
	// For single-node, check minion is running
	// For master, check both master and minion are running
	minionStatus, _ := CheckService(rc, "salt-minion")
	if minionStatus != ServiceStatusActive {
		logger.Debug("Salt minion not active")
		return false, nil
	}
	
	// If master mode, also check master service
	masterStatus, _ := CheckService(rc, "salt-master")
	if masterStatus == ServiceStatusActive || masterStatus == ServiceStatusUnknown {
		// Master is optional for single-node setups
		logger.Debug("Salt services validated")
	}
	
	return true, nil
}

// validateSaltAPIPhase checks if Salt API is properly set up
func validateSaltAPIPhase(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating Salt API setup")
	
	// Create a context with timeout for service checks
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()
	
	// Create a temporary runtime context with timeout
	timeoutRC := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: rc.Log,
	}
	
	// Check if API service is running with timeout
	status, err := CheckService(timeoutRC, "eos-salt-api")
	if err != nil || status != ServiceStatusActive {
		logger.Debug("Salt API service not active", zap.String("status", string(status)))
		return false, nil
	}
	
	// Check if API responds to health check with timeout
	// Add retry logic for API that might be starting up
	retryConfig := RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      2 * time.Second,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
	}
	
	apiResponding := false
	err = WithRetry(timeoutRC, retryConfig, func() error {
		if checkSaltAPIConfigured(timeoutRC) {
			apiResponding = true
			return nil
		}
		return fmt.Errorf("API not responding")
	})
	
	if !apiResponding {
		logger.Debug("Salt API not responding after retries")
		return false, nil
	}
	
	return true, nil
}

// validateStoragePhase checks if storage operations are deployed
func validateStoragePhase(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating storage operations")
	
	// Check if storage-ops service exists and is running
	status, err := CheckService(rc, "storage-ops")
	if err != nil {
		logger.Debug("Storage-ops service check failed", zap.Error(err))
		// Service might not exist, which is OK for optional storage
		return false, nil
	}
	
	if status != ServiceStatusActive {
		logger.Debug("Storage-ops service not active", zap.String("status", string(status)))
		return false, nil
	}
	
	// Check if storage configuration exists
	if _, err := os.Stat("/etc/eos/storage-ops.yaml"); os.IsNotExist(err) {
		logger.Debug("Storage configuration not found")
		return false, nil
	}
	
	// Check if monitoring directory exists
	if _, err := os.Stat("/var/lib/eos/storage-monitoring"); os.IsNotExist(err) {
		logger.Debug("Storage monitoring directory not found")
		return false, nil
	}
	
	logger.Debug("Storage operations validated successfully")
	return true, nil
}

// validateTailscalePhase checks if Tailscale is installed
func validateTailscalePhase(rc *eos_io.RuntimeContext) (bool, error) {
	// Check if tailscaled service exists
	status, _ := CheckService(rc, "tailscaled")
	return status == ServiceStatusActive, nil
}

// validateOSQueryPhase checks if OSQuery is installed
func validateOSQueryPhase(rc *eos_io.RuntimeContext) (bool, error) {
	// Check if osqueryd service exists
	status, _ := CheckService(rc, "osqueryd")
	return status == ServiceStatusActive, nil
}

// validateHardeningPhase checks if hardening was applied
func validateHardeningPhase(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating hardening phase")
	
	// Check for common hardening indicators
	hardeningIndicators := []struct {
		path        string
		description string
		required    bool
	}{
		{"/etc/ssh/sshd_config.d/99-eos-hardened.conf", "SSH hardening config", false},
		{"/etc/security/limits.d/99-eos-limits.conf", "Security limits", false},
		{"/etc/sysctl.d/99-eos-sysctl.conf", "Kernel hardening", false},
		{"/etc/modprobe.d/eos-blacklist.conf", "Module blacklist", false},
	}
	
	hardeningApplied := false
	for _, indicator := range hardeningIndicators {
		if _, err := os.Stat(indicator.path); err == nil {
			logger.Debug("Hardening indicator found", 
				zap.String("file", indicator.path),
				zap.String("type", indicator.description))
			hardeningApplied = true
		} else if indicator.required {
			logger.Debug("Required hardening indicator missing",
				zap.String("file", indicator.path))
			return false, nil
		}
	}
	
	// Check if UFW is enabled (common hardening step)
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	if err == nil && strings.Contains(output, "Status: active") {
		logger.Debug("UFW firewall is active")
		hardeningApplied = true
	}
	
	// Check for fail2ban service
	status, _ := CheckService(rc, "fail2ban")
	if status == ServiceStatusActive {
		logger.Debug("Fail2ban service is active")
		hardeningApplied = true
	}
	
	logger.Debug("Hardening validation complete", zap.Bool("applied", hardeningApplied))
	return hardeningApplied, nil
}

// GetIncompletePhases returns a list of phases that are not complete
func GetIncompletePhases(rc *eos_io.RuntimeContext, phases []BootstrapPhase) []string {
	logger := otelzap.Ctx(rc.Ctx)
	var incomplete []string
	
	for _, phase := range phases {
		if !ValidatePhaseCompletion(rc, phase.Name) {
			logger.Debug("Phase incomplete", zap.String("phase", phase.Name))
			incomplete = append(incomplete, phase.Name)
		}
	}
	
	return incomplete
}

// IsBootstrapComplete checks if all required bootstrap phases are complete
func IsBootstrapComplete(rc *eos_io.RuntimeContext) (bool, []string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking if bootstrap is complete")
	
	// Define required phases
	requiredPhases := []string{"salt", "salt-api"}
	var missingPhases []string
	
	for _, phase := range requiredPhases {
		if !ValidatePhaseCompletion(rc, phase) {
			missingPhases = append(missingPhases, phase)
		}
	}
	
	complete := len(missingPhases) == 0
	logger.Debug("Bootstrap completion check",
		zap.Bool("complete", complete),
		zap.Strings("missing_phases", missingPhases))
	
	return complete, missingPhases
}