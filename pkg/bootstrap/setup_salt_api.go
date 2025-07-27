// pkg/bootstrap/setup_salt_api.go

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

// SetupSaltAPI configures and starts the Salt API service for cluster management
func SetupSaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Salt API service")

	// Check if API is already set up and running
	if isAPIAlreadySetup(rc) {
		logger.Info("Salt API is already configured and running")
		return nil
	}

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

	// Create the API script if it doesn't exist
	if err := createAPIScript(rc); err != nil {
		return fmt.Errorf("failed to create API script: %w", err)
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

	// RACE: [P1] Service might be starting up - no delay between start and check
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

// isAPIAlreadySetup checks if the API is already configured and running
func isAPIAlreadySetup(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if service exists
	status, err := CheckService(rc, "eos-salt-api")
	if err != nil || status != ServiceStatusActive {
		logger.Debug("Salt API service not active", zap.String("status", string(status)))
		return false
	}
	
	// Check if API script exists
	if _, err := os.Stat("/opt/eos/salt/api/cluster_api.py"); os.IsNotExist(err) {
		logger.Debug("Salt API script not found")
		return false
	}
	
	// Check if API responds
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:5000/health"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	if err == nil && strings.TrimSpace(output) == "200" {
		logger.Debug("Salt API is responding")
		return true
	}
	
	return false
}

// createAPIScript creates the Salt API Python script if it doesn't exist
func createAPIScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	scriptPath := "/opt/eos/salt/api/cluster_api.py"
	
	// Check if script already exists
	if _, err := os.Stat(scriptPath); err == nil {
		logger.Debug("API script already exists", zap.String("path", scriptPath))
		return nil
	}
	
	// Ensure /etc/eos directory exists for API key storage
	if err := CreateDirectoryIfMissing("/etc/eos", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/eos directory: %w", err)
	}
	
	logger.Info("Creating Salt API script")
	
	// Create a minimal API with basic authentication
	// Note: This is a temporary implementation - production should use proper auth
	minimalAPI := `#!/usr/bin/env python3
"""Minimal Salt API with basic authentication"""

import os
import secrets
from functools import wraps
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# Generate a random API key on startup if not provided
API_KEY = os.environ.get('EOS_SALT_API_KEY', secrets.token_urlsafe(32))

# Write the API key to a file for other services to read
with open('/etc/eos/salt-api.key', 'w') as f:
    f.write(API_KEY)
os.chmod('/etc/eos/salt-api.key', 0o600)

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            return Response('Unauthorized', 401)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint - no auth required"""
    return jsonify({'status': 'healthy', 'service': 'eos-salt-api'})

@app.route('/cluster/info', methods=['GET'])
@require_api_key
def cluster_info():
    """Basic cluster info endpoint - requires authentication"""
    return jsonify({
        'cluster_id': 'standalone',
        'nodes': 1,
        'status': 'active'
    })

if __name__ == '__main__':
    print(f"API Key: {API_KEY}")
    app.run(host='0.0.0.0', port=5000, debug=False)
`
	
	if err := os.WriteFile(scriptPath, []byte(minimalAPI), 0755); err != nil {
		return fmt.Errorf("failed to create API script: %w", err)
	}
	
	return nil
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
