// pkg/bootstrap/salt_bootstrap.go
//
// Comprehensive Salt and Salt API bootstrap implementation

package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapSaltComplete performs a comprehensive Salt and Salt API setup
func BootstrapSaltComplete(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Salt bootstrap")

	// Phase 1: Validate prerequisites
	if err := validateSaltPrerequisites(rc); err != nil {
		return fmt.Errorf("salt prerequisites check failed: %w", err)
	}

	// Phase 2: Install Salt if needed
	if err := ensureSaltInstalled(rc, info); err != nil {
		return fmt.Errorf("salt installation failed: %w", err)
	}

	// Phase 3: Configure Salt
	if err := configureSalt(rc, info); err != nil {
		return fmt.Errorf("salt configuration failed: %w", err)
	}

	// Phase 4: Set up file roots
	if err := setupSaltFileRoots(rc); err != nil {
		return fmt.Errorf("file roots setup failed: %w", err)
	}

	// Phase 5: Ensure Salt services are running
	if err := ensureSaltServicesRunning(rc, info); err != nil {
		return fmt.Errorf("salt services startup failed: %w", err)
	}

	// Phase 6: Set up Salt API
	if err := SetupSaltAPI(rc); err != nil {
		return fmt.Errorf("salt API setup failed: %w", err)
	}

	// Phase 7: Verify everything is working
	if err := verifySaltSetup(rc); err != nil {
		return fmt.Errorf("salt verification failed: %w", err)
	}

	logger.Info("Salt bootstrap completed successfully")
	return nil
}

// validateSaltPrerequisites checks system requirements for Salt
func validateSaltPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Salt prerequisites")

	// Check root access
	if err := CheckRoot(); err != nil {
		return err
	}

	// Check OS compatibility
	if err := checkUbuntuVersion(rc); err != nil {
		return err
	}

	// Check disk space (Salt needs at least 1GB)
	if err := CheckDiskSpace(rc, "/", 1); err != nil {
		return err
	}

	// Check network connectivity
	if err := checkSaltNetworkConnectivity(rc); err != nil {
		return fmt.Errorf("network connectivity check failed: %w", err)
	}

	logger.Info("Prerequisites validated successfully")
	return nil
}

// ensureSaltInstalled installs Salt if not already present
func ensureSaltInstalled(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Salt is already installed
	if installed, version := checkSaltInstalled(rc); installed {
		logger.Info("Salt is already installed", zap.String("version", version))
		return nil
	}

	logger.Info("Installing SaltStack")

	// Determine installation mode
	masterMode := !info.IsSingleNode || info.IsMaster
	
	config := &saltstack.Config{
		MasterMode: masterMode,
		LogLevel:   "warning",
	}

	// Use the saltstack package installation
	if err := saltstack.Install(rc, config); err != nil {
		return fmt.Errorf("salt installation failed: %w", err)
	}

	return nil
}

// configureSalt applies Salt configuration
func configureSalt(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt")

	// Create configuration directories
	configDirs := []string{
		"/etc/salt",
		"/etc/salt/master.d",
		"/etc/salt/minion.d",
		"/var/cache/salt",
		"/var/log/salt",
	}

	for _, dir := range configDirs {
		if err := CreateDirectoryIfMissing(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Configure based on deployment type
	if info.IsSingleNode {
		if err := configureSaltMasterless(rc); err != nil {
			return err
		}
	} else if info.IsMaster {
		if err := configureSaltMaster(rc); err != nil {
			return err
		}
	} else {
		if err := configureSaltMinionForCluster(rc, info.MasterAddr); err != nil {
			return err
		}
	}

	return nil
}

// configureSaltMasterless sets up Salt for single-node deployment
func configureSaltMasterless(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt for masterless mode")

	// Create masterless configuration
	minionConfig := `# Masterless minion configuration
file_client: local
master_type: disable

# File roots configuration
file_roots:
  base:
    - /srv/salt
    - /opt/eos/salt/states

# Pillar roots
pillar_roots:
  base:
    - /srv/pillar
    - /opt/eos/salt/pillars

# Logging
log_level: warning
log_file: /var/log/salt/minion

# State output
state_output: changes
`

	if err := os.WriteFile("/etc/salt/minion.d/99-masterless.conf", []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write masterless config: %w", err)
	}

	return nil
}

// configureSaltMaster sets up Salt master configuration
func configureSaltMaster(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt master")

	// Create master configuration
	masterConfig := `# Salt master configuration
interface: 0.0.0.0
publish_port: 4505
ret_port: 4506

# File roots configuration
file_roots:
  base:
    - /srv/salt
    - /opt/eos/salt/states

# Pillar roots
pillar_roots:
  base:
    - /srv/pillar
    - /opt/eos/salt/pillars

# Security
keep_jobs: 24
gather_job_timeout: 10

# API configuration
rest_api:
  port: 8000
  ssl_crt: /etc/salt/pki/master/api.crt
  ssl_key: /etc/salt/pki/master/api.key
  webhook_disable_auth: False

# Logging
log_level: warning
log_file: /var/log/salt/master

# Worker configuration
worker_threads: 5
`

	if err := os.WriteFile("/etc/salt/master.d/99-eos.conf", []byte(masterConfig), 0644); err != nil {
		return fmt.Errorf("failed to write master config: %w", err)
	}

	// Also configure local minion to connect to itself
	minionConfig := `# Local minion configuration
master: localhost
id: {{ grains['fqdn'] }}

# Logging
log_level: warning
log_file: /var/log/salt/minion
`

	if err := os.WriteFile("/etc/salt/minion.d/99-local.conf", []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write minion config: %w", err)
	}

	return nil
}

// configureSaltMinionForCluster sets up Salt minion to connect to master
func configureSaltMinionForCluster(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt minion", zap.String("master", masterAddr))

	minionConfig := fmt.Sprintf(`# Minion configuration
master: %s
id: {{ grains['fqdn'] }}

# Retry configuration
master_tries: -1
master_alive_interval: 30

# Logging
log_level: warning
log_file: /var/log/salt/minion

# State output
state_output: changes
`, masterAddr)

	if err := os.WriteFile("/etc/salt/minion.d/99-cluster.conf", []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write minion config: %w", err)
	}

	return nil
}

// setupSaltFileRoots creates and links Salt state directories
func setupSaltFileRoots(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Salt file roots")

	// Create base directories
	dirs := []string{
		"/srv/salt",
		"/srv/pillar",
		"/opt/eos/salt/states",
		"/opt/eos/salt/pillars",
	}

	for _, dir := range dirs {
		if err := CreateDirectoryIfMissing(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create symlinks for Eos states
	links := map[string]string{
		"/srv/salt/hashicorp":     "/opt/eos/salt/states/hashicorp",
		"/srv/salt/dependencies":  "/opt/eos/salt/states/dependencies",
		"/srv/salt/services":      "/opt/eos/salt/states/services",
		"/srv/salt/security":      "/opt/eos/salt/states/security",
		"/srv/salt/storage":       "/opt/eos/salt/states/storage",
		"/srv/salt/networking":    "/opt/eos/salt/states/networking",
		"/srv/salt/monitoring":    "/opt/eos/salt/states/monitoring",
	}
	
	// Track created symlinks for cleanup on failure
	var createdLinks []string
	var returnErr error
	
	// Cleanup function that runs at the end
	defer func() {
		// If we're returning an error, clean up any symlinks we created
		if returnErr != nil && len(createdLinks) > 0 {
			logger.Debug("Cleaning up symlinks due to error", 
				zap.Int("count", len(createdLinks)),
				zap.Error(returnErr))
			for _, link := range createdLinks {
				if err := os.Remove(link); err != nil {
					logger.Debug("Failed to remove symlink during cleanup",
						zap.String("link", link),
						zap.Error(err))
				}
			}
		}
	}()

	for link, target := range links {
		// Remove existing link if it exists
		if _, err := os.Lstat(link); err == nil {
			os.Remove(link)
		}

		// Create parent directory if needed
		linkDir := filepath.Dir(link)
		if err := CreateDirectoryIfMissing(linkDir, 0755); err != nil {
			returnErr = fmt.Errorf("failed to create link directory %s: %w", linkDir, err)
			return returnErr
		}

		// Create symlink
		if err := os.Symlink(target, link); err != nil {
			logger.Warn("Failed to create symlink, trying to create directory",
				zap.String("link", link),
				zap.String("target", target),
				zap.Error(err))
			
			// If target doesn't exist, create it
			if _, err := os.Stat(target); os.IsNotExist(err) {
				if err := CreateDirectoryIfMissing(target, 0755); err != nil {
					// Cleanup will happen in defer
					returnErr = fmt.Errorf("failed to create target directory %s: %w", target, err)
					return returnErr
				}
				// Retry symlink
				if err := os.Symlink(target, link); err != nil {
					// Cleanup will happen in defer
					returnErr = fmt.Errorf("failed to create symlink %s -> %s: %w", link, target, err)
					return returnErr
				}
			}
		}
		
		// Track successfully created symlink
		createdLinks = append(createdLinks, link)
		logger.Debug("Created symlink", zap.String("link", link), zap.String("target", target))
	}

	return nil
}

// ensureSaltServicesRunning starts necessary Salt services
func ensureSaltServicesRunning(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring Salt services are running")

	// Determine which services to start
	var services []string

	if info.IsSingleNode {
		// Masterless mode - only minion
		services = []string{"salt-minion"}
	} else if info.IsMaster {
		// Master node - both master and minion
		services = []string{"salt-master", "salt-minion"}
	} else {
		// Worker node - only minion
		services = []string{"salt-minion"}
	}

	// Start each service
	for _, service := range services {
		logger.Info("Ensuring service is running", zap.String("service", service))
		
		// Use common utility with retry
		if err := EnsureService(rc, service); err != nil {
			// Try to diagnose the issue
			output, _ := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"status", service},
				Capture: true,
			})
			logger.Error("Service failed to start",
				zap.String("service", service),
				zap.String("status", output),
				zap.Error(err))
			return fmt.Errorf("failed to start %s: %w", service, err)
		}
	}

	return nil
}

// verifySaltSetup performs comprehensive verification
func verifySaltSetup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Salt setup")

	// Test Salt command execution
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "test.ping"},
		Capture: true,
	})

	if err != nil || !strings.Contains(output, "True") {
		return fmt.Errorf("salt-call test failed: %w (output: %s)", err, output)
	}

	// Test state listing
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "state.show_top"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to show top state", zap.Error(err))
	}

	// Verify API is accessible
	status, _ := CheckService(rc, "eos-salt-api")
	if status != ServiceStatusActive {
		logger.Warn("Salt API service is not active", zap.String("status", string(status)))
	}

	logger.Info("Salt setup verification completed")
	return nil
}

// Helper functions

func checkUbuntuVersion(rc *eos_io.RuntimeContext) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsb_release",
		Args:    []string{"-rs"},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to check Ubuntu version: %w", err)
	}

	version := strings.TrimSpace(output)
	if version < "20.04" {
		return fmt.Errorf("Ubuntu %s is not supported, minimum version is 20.04", version)
	}

	return nil
}

func checkSaltNetworkConnectivity(rc *eos_io.RuntimeContext) error {
	// BUG: [P3] Only checks DNS resolution, not actual network connectivity
	// FIXME: [P3] No retry logic for transient network failures
	// TODO: [P3] Add proxy configuration support
	// Try to resolve a well-known domain
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"hosts", "github.com"},
		Capture: true,
	})

	if err != nil || output == "" {
		return fmt.Errorf("cannot resolve DNS names - check network configuration")
	}

	return nil
}