//go:build linux

// pkg/consul/client_agent.go
//
// Consul client agent installation for Docker hosts.
//
// This implements HashiCorp's recommended pattern: one Consul agent per Docker host
// in client mode, which monitors Docker containers and registers them as services.
//
// Last Updated: 2025-01-24

package consul

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ClientAgentConfig holds configuration for Consul client agent installation.
type ClientAgentConfig struct {
	NodeName   string   // Node name (default: hostname)
	Datacenter string   // Datacenter name (auto-discovered if empty)
	RetryJoin  []string // Server addresses to join (auto-discovered if empty)
	LogLevel   string   // Log level (default: INFO)
}

// InstallClientAgent installs Consul agent in client mode on Docker host.
//
// This function implements HashiCorp's recommended pattern for Docker + Consul:
//  1. Install Consul binary (or verify existing)
//  2. Create /etc/consul.d/ config directory
//  3. Generate client mode configuration
//  4. Create systemd service
//  5. Start and enable agent
//
// The client agent:
//   - Runs in client mode (not server)
//   - Joins existing Consul cluster
//   - Monitors Docker containers
//   - Registers services from /etc/consul.d/ configs
//   - Uses docker exec for health checks
//
// Parameters:
//   - rc: RuntimeContext
//   - config: Client agent configuration
//
// Returns:
//   - error: Installation error or nil
//
// Example:
//
//	config := consul.ClientAgentConfig{
//	    NodeName: "docker-host-01",
//	}
//	err := consul.InstallClientAgent(rc, config)
func InstallClientAgent(rc *eos_io.RuntimeContext, config ClientAgentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Consul client agent on Docker host",
		zap.String("node_name", config.NodeName))

	// ASSESS - Check if Consul already installed
	consulPath, err := exec.LookPath("consul")
	if err == nil {
		logger.Info("Consul binary already exists",
			zap.String("path", consulPath))

		// Verify version
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"version"},
			Capture: true,
		})
		if err == nil {
			logger.Info("Existing Consul version",
				zap.String("version", strings.Split(output, "\n")[0]))
		}
	} else {
		// Download and install Consul binary
		logger.Info("Consul binary not found, downloading",
			zap.String("version", ConsulDefaultVersion))

		if err := downloadAndInstallConsulBinary(rc, ConsulDefaultVersion); err != nil {
			return fmt.Errorf("failed to install Consul binary: %w", err)
		}
	}

	// ASSESS - Discover environment for retry_join and datacenter
	if config.Datacenter == "" || len(config.RetryJoin) == 0 {
		logger.Info("Discovering environment configuration")

		envConfig, err := environment.DiscoverEnvironment(rc)
		if err != nil {
			logger.Warn("Failed to discover environment, will use provided config",
				zap.Error(err))
		} else {
			if config.Datacenter == "" {
				config.Datacenter = envConfig.Datacenter
			}
			if len(config.RetryJoin) == 0 {
				config.RetryJoin = envConfig.ClusterNodes
			}

			logger.Info("Environment discovered",
				zap.String("datacenter", config.Datacenter),
				zap.Int("retry_join_count", len(config.RetryJoin)))
		}
	}

	// Set defaults
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}

	// INTERVENE - Create config directory
	if err := os.MkdirAll(ConsulConfigDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// INTERVENE - Generate client agent configuration
	clientConfig := generateClientAgentConfig(config)

	// Write config
	configPath := filepath.Join(ConsulConfigDir, "consul.hcl")
	if err := os.WriteFile(configPath, []byte(clientConfig), shared.FilePermStandard); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Client agent configuration written",
		zap.String("config_path", configPath))

	// INTERVENE - Create systemd service
	if err := createClientAgentSystemdService(rc); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	// INTERVENE - Start agent
	logger.Info("Starting Consul client agent")
	if err := startClientAgent(rc); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	// EVALUATE - Verify agent is running
	if err := verifyAgentRunning(rc); err != nil {
		return fmt.Errorf("agent verification failed: %w", err)
	}

	logger.Info("Consul client agent installed successfully",
		zap.String("node_name", config.NodeName),
		zap.String("datacenter", config.Datacenter),
		zap.String("config", configPath))

	return nil
}

// generateClientAgentConfig creates HCL configuration for client agent.
func generateClientAgentConfig(config ClientAgentConfig) string {
	var hcl strings.Builder

	hcl.WriteString("# Consul Client Agent Configuration\n")
	hcl.WriteString("# Generated by Eos\n\n")

	hcl.WriteString(fmt.Sprintf("datacenter = \"%s\"\n", config.Datacenter))
	hcl.WriteString(fmt.Sprintf("node_name  = \"%s\"\n", config.NodeName))
	hcl.WriteString(fmt.Sprintf("data_dir   = \"%s\"\n", ConsulOptDir))
	hcl.WriteString(fmt.Sprintf("log_level  = \"%s\"\n\n", config.LogLevel))

	hcl.WriteString("# Client mode (not server)\n")
	hcl.WriteString("server = false\n\n")

	if len(config.RetryJoin) > 0 {
		hcl.WriteString("# Join Consul cluster\n")
		hcl.WriteString("retry_join = [\n")
		for _, addr := range config.RetryJoin {
			hcl.WriteString(fmt.Sprintf("  \"%s\",\n", addr))
		}
		hcl.WriteString("]\n\n")
	}

	hcl.WriteString("# Enable local script checks (required for Docker health checks)\n")
	hcl.WriteString("enable_local_script_checks = true\n\n")

	hcl.WriteString("# Service definition directory\n")
	hcl.WriteString(fmt.Sprintf("config_dir = \"%s\"\n\n", ConsulConfigDir))

	hcl.WriteString("# UI disabled for client agents\n")
	hcl.WriteString("ui_config {\n")
	hcl.WriteString("  enabled = false\n")
	hcl.WriteString("}\n")

	return hcl.String()
}

// downloadAndInstallConsulBinary downloads and installs Consul binary.
func downloadAndInstallConsulBinary(rc *eos_io.RuntimeContext, version string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Download URL
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_amd64.zip",
		version, version)

	logger.Info("Downloading Consul binary",
		zap.String("url", downloadURL))

	// Download to temp file
	tmpFile := filepath.Join("/tmp", fmt.Sprintf("consul_%s.zip", version))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "wget",
		Args:    []string{"-O", tmpFile, downloadURL},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to download Consul: %s: %w", output, err)
	}

	// Unzip
	logger.Info("Extracting Consul binary")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "unzip",
		Args:    []string{"-o", tmpFile, "-d", "/tmp"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to unzip Consul: %s: %w", output, err)
	}

	// Move to target installation path
	logger.Info("Installing Consul binary", zap.String("target_path", ConsulBinaryPath))
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "mv",
		Args:    []string{"/tmp/consul", ConsulBinaryPath},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to install Consul: %s: %w", output, err)
	}

	// Make executable
	if err := os.Chmod(ConsulBinaryPath, 0755); err != nil {
		return fmt.Errorf("failed to make Consul executable: %w", err)
	}

	// Cleanup
	_ = os.Remove(tmpFile)

	logger.Info("Consul binary installed successfully",
		zap.String("version", version))

	return nil
}

// createClientAgentSystemdService creates systemd service for client agent.
func createClientAgentSystemdService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating systemd service for Consul client agent")

	serviceContent := `[Unit]
Description=Consul Client Agent
Documentation=https://developer.hashicorp.com/consul/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=root
Group=root
ExecStart=` + ConsulBinaryPath + ` agent -config-dir=/etc/consul.d
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

	servicePath := "/etc/systemd/system/consul.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service: %w", err)
	}

	logger.Info("Systemd service created",
		zap.String("service_path", servicePath))

	// Reload systemd
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to reload systemd: %s: %w", output, err)
	}

	return nil
}

// startClientAgent starts and enables the Consul client agent service.
func startClientAgent(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Enable service
	logger.Info("Enabling Consul service")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "consul"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to enable service: %s: %w", output, err)
	}

	// Start service
	logger.Info("Starting Consul service")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", "consul"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to start service: %s: %w", output, err)
	}

	return nil
}

// verifyAgentRunning verifies that the Consul agent is running.
func verifyAgentRunning(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying Consul agent is running")

	// Check systemd status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("consul service is not active: %s", output)
	}

	// Check agent health
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("consul agent not responding: %s: %w", output, err)
	}

	logger.Info("Consul agent is running and healthy")

	return nil
}

// ReloadConsulAgent reloads the Consul agent to pick up new service definitions.
func ReloadConsulAgent(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reloading Consul agent")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"reload", "consul"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to reload Consul agent: %s: %w", output, err)
	}

	logger.Info("Consul agent reloaded successfully")

	return nil
}
