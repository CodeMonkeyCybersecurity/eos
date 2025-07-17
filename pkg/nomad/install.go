// pkg/nomad/install.go

package nomad

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrerequisites verifies that all prerequisites are met for Nomad installation
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Nomad installation prerequisites")
	
	// ASSESS - Check if we're on Ubuntu
	ubuntuRelease, err := platform.DetectUbuntuRelease(rc)
	if err != nil {
		return fmt.Errorf("Nomad installation via SaltStack is only supported on Ubuntu: %w", err)
	}
	logger.Debug("Detected Ubuntu release", zap.String("version", ubuntuRelease.Version))
	
	// Check if SaltStack is installed and running
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("SaltStack minion is not installed or not running: %w", err)
	}
	
	// Check if Consul is running (required for Nomad integration)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Consul service is not running - Nomad will work but without service discovery")
	}
	
	// Check if Vault is running (required for secrets integration)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Vault service is not running - Nomad will work but without secrets integration")
	}
	
	// Check if Docker is available for the Docker driver
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Docker is not available - Nomad will work but without Docker driver")
	}
	
	// Check available disk space
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-h", "/"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Could not check disk space", zap.Error(err))
	} else {
		logger.Debug("Disk space check", zap.String("output", output))
	}
	
	logger.Info("Prerequisites check completed")
	return nil
}

// InstallWithSaltStack installs Nomad using SaltStack
func InstallWithSaltStack(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nomad using SaltStack")
	
	// ASSESS - Check if Nomad is already installed
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err == nil {
		logger.Info("Nomad is already installed, checking version")
		// Could add version comparison logic here
	}
	
	// INTERVENE - Apply SaltStack state for Nomad installation
	logger.Info("Applying SaltStack state for Nomad installation")
	
	// Create pillar data with configuration
	pillarData := fmt.Sprintf(`nomad:
  version: "%s"
  datacenter: "%s"
  region: "%s"
  node_role: "%s"
  enable_ui: %t
  http_port: %d
  rpc_port: %d
  serf_port: %d
  consul_integration: %t
  vault_integration: %t
  consul_address: "%s"
  vault_address: "%s"
  enable_tls: %t
  enable_acl: %t
  enable_gossip: %t
  data_dir: "%s"
  config_dir: "%s"
  log_level: "%s"
  server_bootstrap_expect: %d
  docker_enabled: %t
  exec_enabled: %t
  raw_exec_enabled: %t
  enable_telemetry: %t`,
		config.Version,
		config.Datacenter,
		config.Region,
		config.NodeRole,
		config.EnableUI,
		config.HTTPPort,
		config.RPCPort,
		config.SerfPort,
		config.ConsulIntegration,
		config.VaultIntegration,
		config.ConsulAddress,
		config.VaultAddress,
		config.EnableTLS,
		config.EnableACL,
		config.EnableGossip,
		config.DataDir,
		config.ConfigDir,
		config.LogLevel,
		config.ServerBootstrapExpect,
		config.DockerEnabled,
		config.ExecEnabled,
		config.RawExecEnabled,
		config.EnableTelemetry,
	)
	
	// Write pillar data to temporary file
	pillarFile := "/tmp/nomad-pillar.sls"
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", pillarFile, pillarData)},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to write pillar data: %w", err)
	}
	
	// Apply the Nomad state with pillar data
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"state.apply", "nomad", fmt.Sprintf("pillar=%s", pillarFile), "--output=json"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("SaltStack state apply failed: %w", err)
	}
	
	logger.Debug("SaltStack state execution result", zap.String("output", output))
	
	// Clean up pillar file
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "rm",
		Args:    []string{"-f", pillarFile},
		Capture: true,
	})
	
	// EVALUATE - Verify installation
	logger.Info("Verifying Nomad installation")
	
	// Check if Nomad binary is installed
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad binary not found after installation: %w", err)
	}
	
	// Check if Nomad service is active
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not active: %w", err)
	}
	
	logger.Info("Nomad installation completed successfully")
	return nil
}

// Configure configures Nomad after installation
func Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Nomad")
	
	// ASSESS - Check if Nomad is running
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not running: %w", err)
	}
	
	// INTERVENE - Apply configuration
	logger.Info("Applying Nomad configuration")
	
	// If this is a server node, initialize ACL system
	if config.NodeRole == NodeRoleServer || config.NodeRole == NodeRoleBoth {
		if config.EnableACL {
			logger.Info("Initializing ACL system")
			
			// Check if ACL is already bootstrapped
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"acl", "bootstrap"},
				Capture: true,
			})
			if err != nil {
				logger.Debug("ACL bootstrap failed (may already be initialized)", zap.Error(err))
			} else {
				logger.Info("ACL system bootstrapped successfully")
			}
		}
	}
	
	// Restart Nomad service to apply configuration
	logger.Info("Restarting Nomad service")
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart Nomad service: %w", err)
	}
	
	// Wait for service to be ready
	logger.Info("Waiting for Nomad service to be ready")
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "nomad"},
			Capture: true,
		})
		if err == nil {
			break
		}
		
		if i == maxRetries-1 {
			return fmt.Errorf("Nomad service did not become active after restart")
		}
		
		logger.Debug("Waiting for Nomad service to be active", zap.Int("attempt", i+1))
		time.Sleep(2 * time.Second)
	}
	
	logger.Info("Nomad configuration completed successfully")
	return nil
}

// Verify verifies that Nomad is properly installed and configured
func Verify(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Nomad installation")
	
	// ASSESS - Check service status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not running: %w", err)
	}
	logger.Debug("Service status", zap.String("output", output))
	
	// Check Nomad version
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad version check failed: %w", err)
	}
	logger.Info("Nomad version", zap.String("version", output))
	
	// Check if server is running (if configured as server)
	if config.NodeRole == NodeRoleServer || config.NodeRole == NodeRoleBoth {
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"server", "members"},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("Nomad server members check failed: %w", err)
		}
		logger.Debug("Server members", zap.String("output", output))
	}
	
	// Check if client is running (if configured as client)
	if config.NodeRole == NodeRoleClient || config.NodeRole == NodeRoleBoth {
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"node", "status"},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("Nomad node status check failed: %w", err)
		}
		logger.Debug("Node status", zap.String("output", output))
	}
	
	// Check if UI is accessible (if enabled)
	if config.EnableUI {
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-f", "-s", fmt.Sprintf("http://localhost:%d/ui/", config.HTTPPort)},
			Capture: true,
		})
		if err != nil {
			logger.Warn("Nomad UI is not accessible", zap.Error(err))
		} else {
			logger.Info("Nomad UI is accessible")
		}
	}
	
	// Check API endpoint
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-f", "-s", fmt.Sprintf("http://localhost:%d/v1/status/leader", config.HTTPPort)},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad API is not accessible: %w", err)
	}
	
	logger.Info("Nomad verification completed successfully")
	return nil
}