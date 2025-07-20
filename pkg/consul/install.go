// pkg/consul/install.go

package consul

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
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
	
	// Ask for user consent before proceeding
	consent, err := eos_io.PromptForInstallation(rc, "HashiCorp Consul", "service discovery & mesh networking")
	if err != nil {
		return fmt.Errorf("failed to get user consent: %w", err)
	}
	
	if !consent {
		logger.Info("Installation cancelled by user")
		return fmt.Errorf("installation cancelled by user")
	}

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

	// Create TLS directory
	tlsDir := "/etc/consul.d/tls"
	if err := os.MkdirAll(tlsDir, 0755); err != nil {
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}

	// If certificates are provided, validate and copy them
	if config.CACert != "" && config.ServerCert != "" && config.ServerKey != "" {
		logger.Info("Using provided TLS certificates")
		
		// Validate certificate files exist
		certFiles := map[string]string{
			"CA certificate":     config.CACert,
			"Server certificate": config.ServerCert,
			"Server key":         config.ServerKey,
		}
		
		for name, path := range certFiles {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("%s not found at %s: %w", name, path, err)
			}
		}
		
		// Copy certificates to TLS directory
		caCertDest := filepath.Join(tlsDir, "ca.pem")
		serverCertDest := filepath.Join(tlsDir, "server.pem")
		serverKeyDest := filepath.Join(tlsDir, "server-key.pem")
		
		if err := copyFile(config.CACert, caCertDest); err != nil {
			return fmt.Errorf("failed to copy CA certificate: %w", err)
		}
		
		if err := copyFile(config.ServerCert, serverCertDest); err != nil {
			return fmt.Errorf("failed to copy server certificate: %w", err)
		}
		
		if err := copyFile(config.ServerKey, serverKeyDest); err != nil {
			return fmt.Errorf("failed to copy server key: %w", err)
		}
		
		// Update config paths to point to copied files
		config.CACert = caCertDest
		config.ServerCert = serverCertDest
		config.ServerKey = serverKeyDest
		
		// Set proper permissions
		if err := os.Chmod(serverKeyDest, 0600); err != nil {
			return fmt.Errorf("failed to set server key permissions: %w", err)
		}
		
	} else {
		logger.Info("Generating self-signed TLS certificates")
		
		// Generate self-signed certificates
		if err := generateSelfSignedCerts(rc, config, tlsDir); err != nil {
			return fmt.Errorf("failed to generate self-signed certificates: %w", err)
		}
	}

	// Set ownership of TLS directory
	if err := exec.Command("chown", "-R", "consul:consul", tlsDir).Run(); err != nil {
		return fmt.Errorf("failed to set ownership on TLS directory: %w", err)
	}

	logger.Info("TLS configuration completed")
	return nil
}

func setupACL(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up ACL configuration")

	// ACL setup is primarily handled in configuration generation
	// and bootstrap process. This function prepares the environment
	// for ACL bootstrapping.

	// Create ACL directory for tokens
	aclDir := "/etc/consul.d/acl"
	if err := os.MkdirAll(aclDir, 0755); err != nil {
		return fmt.Errorf("failed to create ACL directory: %w", err)
	}

	// Set ownership
	if err := exec.Command("chown", "-R", "consul:consul", aclDir).Run(); err != nil {
		return fmt.Errorf("failed to set ownership on ACL directory: %w", err)
	}

	// Create ACL configuration file
	aclConfig := map[string]interface{}{
		"acl": map[string]interface{}{
			"enabled":                    true,
			"default_policy":             "deny",
			"enable_token_persistence":   true,
			"enable_token_replication":   config.Mode == "server",
			"down_policy":               "extend-cache",
			"token_ttl":                 "30s",
		},
	}

	aclConfigPath := filepath.Join(aclDir, "acl.json")
	if err := writeConfigFile(aclConfigPath, aclConfig); err != nil {
		return fmt.Errorf("failed to write ACL configuration: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(aclConfigPath, 0644); err != nil {
		return fmt.Errorf("failed to set ACL config permissions: %w", err)
	}

	logger.Info("ACL configuration setup completed")
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

	// Create monitoring directory
	monitoringDir := "/etc/consul.d/monitoring"
	if err := os.MkdirAll(monitoringDir, 0755); err != nil {
		return fmt.Errorf("failed to create monitoring directory: %w", err)
	}

	// Configure telemetry
	telemetryConfig := map[string]interface{}{
		"telemetry": map[string]interface{}{
			"prometheus_retention_time": config.Telemetry.PrometheusRetentionTime,
			"disable_hostname":          config.Telemetry.DisableHostname,
			"statsd_address":           config.Telemetry.StatsdAddr,
			"dogstatsd_address":        config.Telemetry.DogstatsdAddr,
			"metrics_prefix":           "consul",
			"filter_default":           true,
			"prefix_filter": []string{
				"+consul.runtime",
				"+consul.raft",
				"+consul.serf",
				"+consul.catalog",
				"+consul.health",
				"+consul.http",
				"+consul.acl",
				"+consul.autopilot",
				"+consul.txn",
				"+consul.kvs",
				"+consul.connect",
				"+consul.leader",
				"+consul.dns",
				"+consul.rpc",
			},
		},
	}

	telemetryConfigPath := filepath.Join(monitoringDir, "telemetry.json")
	if err := writeConfigFile(telemetryConfigPath, telemetryConfig); err != nil {
		return fmt.Errorf("failed to write telemetry configuration: %w", err)
	}

	// Configure logging
	loggingConfig := map[string]interface{}{
		"log_level":        config.Logging.LogLevel,
		"log_file":         config.Logging.LogFile,
		"log_rotate_bytes": 10485760, // 10MB
		"log_rotate_duration": "24h",
		"log_rotate_max_files": 5,
		"enable_syslog":    config.Logging.EnableSyslog,
		"enable_json_logs": config.Logging.EnableJSON,
	}

	loggingConfigPath := filepath.Join(monitoringDir, "logging.json")
	if err := writeConfigFile(loggingConfigPath, loggingConfig); err != nil {
		return fmt.Errorf("failed to write logging configuration: %w", err)
	}

	// Configure health checks
	healthConfig := map[string]interface{}{
		"checks": []map[string]interface{}{
			{
				"id":                  "consul-health",
				"name":               "Consul Health Check",
				"http":               fmt.Sprintf("http://localhost:%d/v1/status/leader", config.Ports.HTTP),
				"interval":           "10s",
				"timeout":            "5s",
				"deregister_critical_service_after": "30s",
			},
		},
	}

	healthConfigPath := filepath.Join(monitoringDir, "health.json")
	if err := writeConfigFile(healthConfigPath, healthConfig); err != nil {
		return fmt.Errorf("failed to write health configuration: %w", err)
	}

	// Set ownership
	if err := exec.Command("chown", "-R", "consul:consul", monitoringDir).Run(); err != nil {
		return fmt.Errorf("failed to set ownership on monitoring directory: %w", err)
	}

	logger.Info("Monitoring configuration completed")
	return nil
}

func writeConfigFile(path string, content interface{}) error {
	// Serialize configuration to JSON
	jsonData, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}

func generateMainConfig(config *ConsulConfig) interface{} {
	mainConfig := map[string]interface{}{
		"datacenter":    config.Datacenter,
		"data_dir":      "/opt/consul/data",
		"log_level":     config.Logging.LogLevel,
		"node_name":     config.NodeName,
		"bind_addr":     config.BindAddr,
		"client_addr":   config.ClientAddr,
		"server":        config.Mode == "server",
		"ui_config": map[string]interface{}{
			"enabled": config.EnableUI,
		},
		"connect": map[string]interface{}{
			"enabled": config.ConnectEnabled,
		},
		"ports": map[string]interface{}{
			"grpc":     config.Ports.GRPC,
			"http":     config.Ports.HTTP,
			"https":    config.Ports.HTTPS,
			"serf_lan": config.Ports.SerfLAN,
			"serf_wan": config.Ports.SerfWAN,
			"server":   config.Ports.Server,
			"dns":      config.Ports.DNS,
		},
		"performance": map[string]interface{}{
			"raft_multiplier": config.Performance.RaftMultiplier,
		},
		"telemetry": map[string]interface{}{
			"prometheus_retention_time": config.Telemetry.PrometheusRetentionTime,
			"disable_hostname":          config.Telemetry.DisableHostname,
		},
	}

	// Add advertise address if specified
	if config.AdvertiseAddr != "" {
		mainConfig["advertise_addr"] = config.AdvertiseAddr
	}

	// Add gossip encryption if enabled
	if config.GossipKey != "" {
		mainConfig["encrypt"] = config.GossipKey
	}

	// Add ACL configuration if enabled
	if config.EnableACL {
		mainConfig["acl"] = map[string]interface{}{
			"enabled":        true,
			"default_policy": "deny",
			"enable_token_persistence": true,
		}
	}

	// Add TLS configuration if enabled
	if config.EnableTLS {
		mainConfig["tls"] = map[string]interface{}{
			"defaults": map[string]interface{}{
				"ca_file":         config.CACert,
				"cert_file":       config.ServerCert,
				"key_file":        config.ServerKey,
				"verify_incoming": true,
				"verify_outgoing": true,
			},
			"internal_rpc": map[string]interface{}{
				"verify_server_hostname": true,
			},
		}
	}

	// Add retry join if specified
	if len(config.RetryJoin) > 0 {
		mainConfig["retry_join"] = config.RetryJoin
	}

	return mainConfig
}

func generateServerConfig(config *ConsulConfig) interface{} {
	serverConfig := map[string]interface{}{
		"bootstrap_expect": config.BootstrapExpect,
		"leave_on_terminate": config.Performance.LeaveOnTerm,
		"skip_leave_on_interrupt": config.Performance.SkipLeaveOnInt,
		"rejoin_after_leave": config.Performance.RejoinAfterLeave,
	}

	// Add join addresses if specified
	if len(config.JoinAddresses) > 0 {
		serverConfig["start_join"] = config.JoinAddresses
	}

	// Add mesh gateway configuration if enabled
	if config.MeshGateway {
		serverConfig["mesh_gateway"] = map[string]interface{}{
			"mode": "local",
		}
	}

	// Add ingress gateway configuration if enabled
	if config.IngressGateway {
		serverConfig["ingress_gateway"] = map[string]interface{}{
			"enabled": true,
		}
	}

	return serverConfig
}

func generateClientConfig(config *ConsulConfig) interface{} {
	clientConfig := map[string]interface{}{
		"leave_on_terminate": config.Performance.LeaveOnTerm,
		"skip_leave_on_interrupt": config.Performance.SkipLeaveOnInt,
		"rejoin_after_leave": config.Performance.RejoinAfterLeave,
	}

	// Add join addresses if specified
	if len(config.JoinAddresses) > 0 {
		clientConfig["start_join"] = config.JoinAddresses
	}

	// Add retry join if specified
	if len(config.RetryJoin) > 0 {
		clientConfig["retry_join"] = config.RetryJoin
	}

	return clientConfig
}

func generateBootstrapConfig(config *ConsulConfig) interface{} {
	bootstrapConfig := map[string]interface{}{
		"bootstrap_expect": config.BootstrapExpect,
		"server": true,
	}

	// Bootstrap config typically has minimal settings
	// to avoid conflicts during cluster formation
	return bootstrapConfig
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

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// generateSelfSignedCerts generates self-signed certificates for Consul
func generateSelfSignedCerts(rc *eos_io.RuntimeContext, config *ConsulConfig, tlsDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating self-signed certificates")

	// Generate CA certificate
	caKey, caCert, err := generateCA(config.NodeName)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate server certificate
	serverKey, serverCert, err := generateServerCert(caCert, caKey, config.NodeName)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Write CA certificate
	caCertPath := filepath.Join(tlsDir, "ca.pem")
	if err := writeCertToPEM(caCert, caCertPath); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write server certificate
	serverCertPath := filepath.Join(tlsDir, "server.pem")
	if err := writeCertToPEM(serverCert, serverCertPath); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write server key
	serverKeyPath := filepath.Join(tlsDir, "server-key.pem")
	if err := writeKeyToPEM(serverKey, serverKeyPath); err != nil {
		return fmt.Errorf("failed to write server key: %w", err)
	}

	// Update config paths
	config.CACert = caCertPath
	config.ServerCert = serverCertPath
	config.ServerKey = serverKeyPath

	logger.Info("Self-signed certificates generated successfully")
	return nil
}

// generateCA generates a CA certificate and private key
func generateCA(commonName string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Consul"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    fmt.Sprintf("Consul CA %s", commonName),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse CA certificate
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caKey, caCert, nil
}

// generateServerCert generates a server certificate signed by the CA
func generateServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Consul"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    commonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{commonName, "localhost", "consul.service.consul"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	// Create server certificate
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse server certificate
	serverCert, err := x509.ParseCertificate(serverCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	return serverKey, serverCert, nil
}

// writeCertToPEM writes a certificate to a PEM file
func writeCertToPEM(cert *x509.Certificate, path string) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, certPEM); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}

// writeKeyToPEM writes a private key to a PEM file
func writeKeyToPEM(key *rsa.PrivateKey, path string) error {
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, keyPEM); err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Set restricted permissions on the key file
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	return nil
}