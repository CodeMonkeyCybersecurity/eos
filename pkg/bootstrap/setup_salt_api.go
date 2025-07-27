// pkg/bootstrap/setup_salt_api.go

package bootstrap

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupSaltAPI configures and starts the Salt API service for cluster management
func SetupSaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Salt API service")

	// ASSESS - Ensure Salt master is running (required for API)
	// For single-node deployments, we may need to start it
	if err := ensureSaltMasterRunning(rc); err != nil {
		return fmt.Errorf("failed to ensure Salt master is running: %w", err)
	}

	// Install Flask and dependencies
	if err := installPythonDependencies(rc); err != nil {
		return fmt.Errorf("failed to install Python dependencies: %w", err)
	}

	// INTERVENE - Create API directories and copy service files
	if err := createAPIDirectories(rc); err != nil {
		return fmt.Errorf("failed to create API directories: %w", err)
	}

	if err := installAPIService(rc); err != nil {
		return fmt.Errorf("failed to install API service: %w", err)
	}

	// Start the API service
	if err := startAPIService(rc); err != nil {
		return fmt.Errorf("failed to start API service: %w", err)
	}

	// EVALUATE - Verify API is responding
	if err := verifyAPIService(rc); err != nil {
		return fmt.Errorf("API service verification failed: %w", err)
	}

	logger.Info("Salt API service setup completed successfully")
	return nil
}


// installPythonDependencies installs required Python packages
func installPythonDependencies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Python dependencies for Salt API")

	packages := []string{
		"python3-flask",
		"python3-yaml",
		"python3-salt",
	}

	// Install packages using common utility for idempotency
	for _, pkg := range packages {
		if err := InstallPackageIfMissing(rc, pkg); err != nil {
			return fmt.Errorf("failed to install %s: %w", pkg, err)
		}
	}

	logger.Info("Python dependencies installed successfully")
	return nil
}

// createAPIDirectories creates necessary directories for the API service
func createAPIDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating API directories")

	directories := []string{
		"/opt/eos/salt/api",
		"/var/lib/eos",
		"/var/log/eos",
	}

	for _, dir := range directories {
		if err := CreateDirectoryIfMissing(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Ensured directory exists", zap.String("directory", dir))
	}

	return nil
}

// installAPIService installs the systemd service for Salt API
func installAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Salt API systemd service")

	// Copy service file to systemd directory
	srcPath := "/opt/eos/salt/api/eos-salt-api.service"
	destPath := "/etc/systemd/system/eos-salt-api.service"

	// Read service file
	content, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	// Write to systemd directory
	if err := os.WriteFile(destPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd daemon
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	logger.Debug("Salt API service installed")
	return nil
}

// startAPIService starts and enables the Salt API service
func startAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Salt API service")

	// Enable the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to enable API service: %w", err)
	}

	// Start the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to start API service: %w", err)
	}

	// Wait a moment for service to start
	time.Sleep(3 * time.Second)

	logger.Info("Salt API service started")
	return nil
}

// verifyAPIService verifies the API service is responding
func verifyAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Salt API service")

	// First check if the service is active
	status, err := CheckService(rc, "eos-salt-api")
	if err != nil || status != ServiceStatusActive {
		return fmt.Errorf("eos-salt-api service is not active (status: %s)", status)
	}

	// Create API client and test health check with retry
	apiClient := NewSaltAPIClient(rc, "localhost")

	// Use retry logic for API availability
	retryConfig := RetryConfig{
		MaxAttempts:       6,
		InitialDelay:      5 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 1.5,
	}

	err = WithRetry(rc, retryConfig, func() error {
		// Wait for API to respond
		if err := apiClient.WaitForAPI(rc.Ctx, 10*time.Second); err != nil {
			return fmt.Errorf("API not responding: %w", err)
		}

		// Test a simple API call
		_, err := apiClient.GetClusterInfo()
		if err != nil {
			logger.Debug("Cluster info call failed (expected during bootstrap)", zap.Error(err))
			// This is OK - cluster might not be fully configured yet
			// We just need to know the API is responding
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("API verification failed: %w", err)
	}

	logger.Info("Salt API service verification completed")
	return nil
}

// RestartSaltAPI restarts the Salt API service
func RestartSaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting Salt API service")

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to restart API service: %w", err)
	}

	// Wait for service to restart
	time.Sleep(3 * time.Second)

	// Verify it's working
	return verifyAPIService(rc)
}

// GetSaltAPIStatus returns the status of the Salt API service
func GetSaltAPIStatus(rc *eos_io.RuntimeContext) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "eos-salt-api.service"},
		Capture: true,
	})

	if err != nil {
		return "unknown", err
	}

	return output, nil
}

// ensureSaltMasterRunning ensures Salt master service is running, starting it if necessary
func ensureSaltMasterRunning(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring Salt master service is running")

	// Use common utility to check and ensure service is running
	status, err := CheckService(rc, "salt-master")
	if err == nil && status == ServiceStatusActive {
		logger.Debug("Salt master is already running")
		return nil
	}

	// Check if salt-master package is installed
	installed, err := CheckPackageInstalled(rc, "salt-master")
	if err != nil {
		return fmt.Errorf("failed to check salt-master package: %w", err)
	}

	if !installed {
		logger.Info("Salt master not installed, installing it")
		if err := InstallPackageIfMissing(rc, "salt-master"); err != nil {
			return fmt.Errorf("failed to install salt-master: %w", err)
		}
	}

	// Use common utility to ensure service is running with retry
	return EnsureService(rc, "salt-master")
}
