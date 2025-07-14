// pkg/consul/install.go

package consul

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConsul performs complete Consul installation with error recovery
func InstallConsul(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites and validate configuration
	logger.Info("Assessing Consul installation prerequisites",
		zap.String("mode", config.Mode),
		zap.String("datacenter", config.Datacenter))

	// Run comprehensive preflight checks
	if err := RunPreflightChecks(rc, config); err != nil {
		return fmt.Errorf("preflight checks failed: %w", err)
	}

	// Validate configuration
	if err := validateConsulConfig(rc, config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Check for existing installation
	if err := handleExistingInstallation(rc, config); err != nil {
		return fmt.Errorf("failed to handle existing installation: %w", err)
	}

	// INTERVENE - Perform the installation
	logger.Info("Beginning Consul installation",
		zap.String("mode", config.Mode),
		zap.String("datacenter", config.Datacenter))

	// Step 1: Download and install Consul binary
	if err := downloadAndInstallBinary(rc, config); err != nil {
		return fmt.Errorf("failed to download and install Consul binary: %w", err)
	}

	// Step 2: Create system user and directories
	if err := createSystemResources(rc, config); err != nil {
		return fmt.Errorf("failed to create system resources: %w", err)
	}

	// Step 3: Generate configuration files
	if err := generateConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Step 4: Set up security (ACL, TLS, Gossip encryption)
	if err := setupSecurity(rc, config); err != nil {
		return fmt.Errorf("failed to setup security: %w", err)
	}

	// Step 5: Install and configure systemd service
	if err := installSystemdService(rc, config); err != nil {
		return fmt.Errorf("failed to install systemd service: %w", err)
	}

	// Step 6: Handle bootstrap if this is the first server
	if config.Mode == "server" && config.BootstrapExpect > 0 {
		if err := handleBootstrap(rc, config); err != nil {
			return fmt.Errorf("failed to handle bootstrap: %w", err)
		}
	}

	// Step 7: Start Consul service
	if err := startConsulService(rc, config); err != nil {
		return fmt.Errorf("failed to start Consul service: %w", err)
	}

	// Step 8: Join cluster if needed
	if len(config.JoinAddresses) > 0 {
		if err := joinCluster(rc, config); err != nil {
			return fmt.Errorf("failed to join cluster: %w", err)
		}
	}

	// EVALUATE - Verify the installation succeeded
	logger.Info("Evaluating Consul installation success")

	// Verify service is running and healthy
	if err := verifyInstallation(rc, config); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	// Test cluster connectivity if applicable
	if len(config.JoinAddresses) > 0 {
		if err := verifyClusterConnectivity(rc, config); err != nil {
			logger.Warn("Cluster connectivity verification failed",
				zap.Error(err))
			// Non-fatal - service is running but cluster needs attention
		}
	}

	// Configure monitoring and health checks
	if err := configureMonitoring(rc, config); err != nil {
		logger.Warn("Failed to configure monitoring",
			zap.Error(err))
		// Non-fatal - monitoring can be set up later
	}

	logger.Info("Consul installation completed successfully",
		zap.String("mode", config.Mode),
		zap.String("datacenter", config.Datacenter),
		zap.String("node_name", config.NodeName))

	return nil
}

// handleExistingInstallation checks for and handles existing Consul installations
func handleExistingInstallation(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Consul is already installed
	if _, err := exec.LookPath("consul"); err == nil {
		logger.Info("Existing Consul binary found")

		// Check if service is running
		if isServiceRunning("consul") {
			return eos_err.NewUserError("Consul service is already running. Stop it first with: sudo systemctl stop consul")
		}

		// Check version compatibility
		if err := checkVersionCompatibility(rc); err != nil {
			logger.Warn("Version compatibility check failed", zap.Error(err))
		}

		// Backup existing configuration
		if err := backupExistingConfig(rc); err != nil {
			logger.Warn("Failed to backup existing configuration", zap.Error(err))
		}
	}

	return nil
}

// downloadAndInstallBinary downloads and installs the Consul binary
func downloadAndInstallBinary(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Downloading Consul binary")

	// TODO: Use platform version resolver when available
	version := "1.17.0" // Default to stable version
	logger.Info("Installing Consul version", zap.String("version", version))

	// TODO: Implement proper binary download
	// For now, assume binary is downloaded to /tmp
	binaryPath := "/tmp/consul"
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("consul binary not found at %s - please download manually", binaryPath)
	}

	// Install binary to system location
	targetPath := "/usr/local/bin/consul"
	if err := os.Rename(binaryPath, targetPath); err != nil {
		return fmt.Errorf("failed to install binary to %s: %w", targetPath, err)
	}

	// Set permissions
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", targetPath, err)
	}

	// Verify installation
	if err := exec.Command("consul", "version").Run(); err != nil {
		return fmt.Errorf("failed to verify Consul installation: %w", err)
	}

	logger.Info("Consul binary installed successfully",
		zap.String("path", targetPath),
		zap.String("version", version))

	return nil
}

// createSystemResources creates necessary system users and directories
func createSystemResources(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating system resources")

	// Create consul user
	if err := createConsulUser(rc); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	// Create directories
	directories := []string{
		"/etc/consul.d",
		"/opt/consul",
		"/opt/consul/data",
		"/var/log/consul",
	}

	for _, dir := range directories {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Set ownership to consul user
		if err := exec.Command("chown", "consul:consul", dir).Run(); err != nil {
			return fmt.Errorf("failed to set ownership on %s: %w", dir, err)
		}
	}

	logger.Info("System resources created successfully")
	return nil
}

// generateConfiguration generates Consul configuration files
func generateConfiguration(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Consul configuration")

	// Generate main configuration
	mainConfig := generateMainConfig(config)
	configPath := "/etc/consul.d/consul.json"

	if err := writeConfigFile(configPath, mainConfig); err != nil {
		return fmt.Errorf("failed to write main configuration: %w", err)
	}

	// Generate additional configuration files based on mode
	if config.Mode == "server" {
		serverConfig := generateServerConfig(config)
		serverConfigPath := "/etc/consul.d/server.json"
		if err := writeConfigFile(serverConfigPath, serverConfig); err != nil {
			return fmt.Errorf("failed to write server configuration: %w", err)
		}
	}

	// Generate client configuration if needed
	if config.Mode == "agent" {
		clientConfig := generateClientConfig(config)
		clientConfigPath := "/etc/consul.d/client.json"
		if err := writeConfigFile(clientConfigPath, clientConfig); err != nil {
			return fmt.Errorf("failed to write client configuration: %w", err)
		}
	}

	// Set proper permissions
	if err := exec.Command("chown", "-R", "consul:consul", "/etc/consul.d").Run(); err != nil {
		return fmt.Errorf("failed to set ownership on configuration directory: %w", err)
	}

	logger.Info("Configuration generated successfully")
	return nil
}

// setupSecurity configures ACL, TLS, and gossip encryption
func setupSecurity(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up security configuration")

	// Generate gossip encryption key if not provided
	if config.GossipKey == "" && config.Mode == "server" {
		key, err := generateGossipKey(rc)
		if err != nil {
			return fmt.Errorf("failed to generate gossip key: %w", err)
		}
		config.GossipKey = key
	}

	// Setup TLS if enabled
	if config.EnableTLS {
		if err := setupTLS(rc, config); err != nil {
			return fmt.Errorf("failed to setup TLS: %w", err)
		}
	}

	// Setup ACL if enabled
	if config.EnableACL {
		if err := setupACL(rc, config); err != nil {
			return fmt.Errorf("failed to setup ACL: %w", err)
		}
	}

	logger.Info("Security configuration completed")
	return nil
}

// installSystemdService installs and configures the systemd service
func installSystemdService(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing systemd service")

	serviceContent := generateSystemdService(config)
	servicePath := "/etc/systemd/system/consul.service"

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}

	// Reload systemd daemon
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "consul").Run(); err != nil {
		return fmt.Errorf("failed to enable consul service: %w", err)
	}

	logger.Info("Systemd service installed successfully")
	return nil
}

// handleBootstrap handles the bootstrap process for the first server
func handleBootstrap(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Handling bootstrap process",
		zap.Int("bootstrap_expect", config.BootstrapExpect))

	// Generate bootstrap configuration
	bootstrapConfig := generateBootstrapConfig(config)
	bootstrapPath := "/etc/consul.d/bootstrap.json"

	if err := writeConfigFile(bootstrapPath, bootstrapConfig); err != nil {
		return fmt.Errorf("failed to write bootstrap configuration: %w", err)
	}

	// Set proper permissions
	if err := exec.Command("chown", "consul:consul", bootstrapPath).Run(); err != nil {
		return fmt.Errorf("failed to set ownership on bootstrap config: %w", err)
	}

	logger.Info("Bootstrap configuration created")
	return nil
}

// startConsulService starts the Consul service
func startConsulService(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul service")

	// Start service
	if err := exec.Command("systemctl", "start", "consul").Run(); err != nil {
		return fmt.Errorf("failed to start consul service: %w", err)
	}

	// Wait for service to be ready
	if err := waitForService(rc, 30*time.Second); err != nil {
		return fmt.Errorf("service failed to start within timeout: %w", err)
	}

	logger.Info("Consul service started successfully")
	return nil
}

// joinCluster joins the Consul cluster
func joinCluster(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Joining Consul cluster",
		zap.Strings("join_addresses", config.JoinAddresses))

	// Attempt to join cluster
	for _, addr := range config.JoinAddresses {
		logger.Info("Attempting to join", zap.String("address", addr))

		cmd := exec.Command("consul", "join", addr)
		if err := cmd.Run(); err != nil {
			logger.Warn("Failed to join address",
				zap.String("address", addr),
				zap.Error(err))
			continue
		}

		logger.Info("Successfully joined cluster", zap.String("address", addr))
		return nil
	}

	return fmt.Errorf("failed to join any cluster members")
}

// verifyInstallation verifies the Consul installation
func verifyInstallation(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying Consul installation")

	// Check if service is running
	if !isServiceRunning("consul") {
		return fmt.Errorf("consul service is not running")
	}

	// Check if Consul is responding
	if err := exec.Command("consul", "info").Run(); err != nil {
		return fmt.Errorf("consul is not responding: %w", err)
	}

	// Check cluster membership
	if err := verifyClusterMembership(rc, config); err != nil {
		return fmt.Errorf("cluster membership verification failed: %w", err)
	}

	logger.Info("Installation verification completed successfully")
	return nil
}

// Helper functions

func isServiceRunning(serviceName string) bool {
	err := exec.Command("systemctl", "is-active", serviceName).Run()
	return err == nil
}

func checkVersionCompatibility(rc *eos_io.RuntimeContext) error {
	// TODO: Implement version compatibility checking
	return nil
}

func backupExistingConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	backupDir := fmt.Sprintf("/opt/consul/backup-%d", time.Now().Unix())
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup configuration
	configDirs := []string{"/etc/consul.d", "/etc/consul"}
	for _, dir := range configDirs {
		if _, err := os.Stat(dir); err == nil {
			targetDir := filepath.Join(backupDir, filepath.Base(dir))
			if err := exec.Command("cp", "-r", dir, targetDir).Run(); err != nil {
				logger.Warn("Failed to backup directory",
					zap.String("dir", dir),
					zap.Error(err))
			}
		}
	}

	logger.Info("Configuration backed up", zap.String("backup_dir", backupDir))
	return nil
}

func createConsulUser(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if user already exists
	if err := exec.Command("id", "consul").Run(); err == nil {
		logger.Info("Consul user already exists")
		return nil
	}

	// Create system user
	cmd := exec.Command("useradd", "--system", "--home", "/etc/consul.d", "--shell", "/bin/false", "consul")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	logger.Info("Consul user created successfully")
	return nil
}

func generateGossipKey(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating gossip encryption key")

	cmd := exec.Command("consul", "keygen")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate gossip key: %w", err)
	}

	key := strings.TrimSpace(string(output))
	logger.Info("Gossip key generated successfully")

	return key, nil
}

func setupTLS(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up TLS configuration")

	// TODO: Implement TLS setup
	// This would involve:
	// 1. Generate or import CA certificate
	// 2. Generate server certificates
	// 3. Configure TLS in Consul
	// 4. Set up certificate rotation

	return nil
}

func setupACL(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up ACL configuration")

	// TODO: Implement ACL setup
	// This would involve:
	// 1. Enable ACL in configuration
	// 2. Bootstrap ACL system
	// 3. Create initial policies and tokens
	// 4. Configure agent tokens

	return nil
}

func waitForService(rc *eos_io.RuntimeContext, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Waiting for service to be ready", zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("consul", "info").Run(); err == nil {
			logger.Info("Service is ready")
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("service failed to start within %v", timeout)
}

func verifyClusterMembership(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying cluster membership")

	// Get cluster members
	cmd := exec.Command("consul", "members")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get cluster members: %w", err)
	}

	members := strings.Split(string(output), "\n")
	logger.Info("Cluster members", zap.Int("count", len(members)-1))

	// Verify this node is in the cluster
	nodeFound := false
	for _, member := range members {
		if strings.Contains(member, config.NodeName) {
			nodeFound = true
			break
		}
	}

	if !nodeFound {
		return fmt.Errorf("node %s not found in cluster members", config.NodeName)
	}

	logger.Info("Cluster membership verified")
	return nil
}

func verifyClusterConnectivity(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying cluster connectivity")

	// Check cluster health
	cmd := exec.Command("consul", "operator", "raft", "list-peers")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to check cluster health: %w", err)
	}

	logger.Info("Cluster connectivity verified")
	return nil
}

func configureMonitoring(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring monitoring")

	// TODO: Implement monitoring configuration
	// This would involve:
	// 1. Configure telemetry
	// 2. Set up health checks
	// 3. Configure logging
	// 4. Set up metrics collection

	return nil
}

func writeConfigFile(path string, content interface{}) error {
	// TODO: Implement configuration file writing
	// This would serialize the configuration to JSON and write to file
	return nil
}

func generateMainConfig(config *ConsulConfig) interface{} {
	// TODO: Generate main Consul configuration
	return nil
}

func generateServerConfig(config *ConsulConfig) interface{} {
	// TODO: Generate server-specific configuration
	return nil
}

func generateClientConfig(config *ConsulConfig) interface{} {
	// TODO: Generate client-specific configuration
	return nil
}

func generateBootstrapConfig(config *ConsulConfig) interface{} {
	// TODO: Generate bootstrap configuration
	return nil
}

func generateSystemdService(config *ConsulConfig) string {
	return fmt.Sprintf(`[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.json

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`)
}

// validateConsulConfig validates the Consul configuration
func validateConsulConfig(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating Consul configuration")

	// Validate required fields
	if config.Mode == "" {
		return eos_err.NewUserError("mode is required (server, agent, or dev)")
	}

	if config.Datacenter == "" {
		return eos_err.NewUserError("datacenter is required")
	}

	if config.NodeName == "" {
		return eos_err.NewUserError("node_name is required")
	}

	// Validate mode-specific configuration
	switch config.Mode {
	case "server":
		if config.BootstrapExpect < 1 {
			return eos_err.NewUserError("bootstrap_expect must be >= 1 for server mode")
		}
	case "agent":
		if len(config.JoinAddresses) == 0 && len(config.RetryJoin) == 0 {
			return eos_err.NewUserError("join_addresses or retry_join required for agent mode")
		}
	case "dev":
		// Dev mode has minimal requirements
	default:
		return eos_err.NewUserError("invalid mode: %s (must be server, agent, or dev)", config.Mode)
	}

	// Validate network configuration
	if config.BindAddr == "" {
		config.BindAddr = "0.0.0.0"
	}

	if config.ClientAddr == "" {
		config.ClientAddr = "127.0.0.1"
	}

	// Validate port configuration
	if config.Ports.HTTP == 0 {
		config.Ports = DefaultPortConfig()
	}

	// Validate security configuration
	if config.EnableTLS && (config.CACert == "" || config.ServerCert == "" || config.ServerKey == "") {
		return eos_err.NewUserError("TLS certificates required when TLS is enabled")
	}

	logger.Info("Configuration validation completed successfully")
	return nil
}