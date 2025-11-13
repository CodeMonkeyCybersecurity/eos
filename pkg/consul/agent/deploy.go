// pkg/consul/agent/deploy.go
//
// Main orchestration for Consul agent deployment across platforms.
// Implements the ASSESS → INTERVENE → EVALUATE pattern.
//
// Last Updated: 2025-01-24

package agent

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployAgent deploys a Consul agent using the specified deployment target.
//
// This is the main entry point for all Consul agent deployments. It handles:
//   - Environment discovery and configuration
//   - Secret management initialization
//   - Target-specific deployment delegation
//   - Post-deployment verification
//
// ASSESS → INTERVENE → EVALUATE pattern:
//
//	ASSESS: Validate config, check prerequisites, discover environment
//	INTERVENE: Deploy agent via target-specific method
//	EVALUATE: Verify deployment, register services, check health
//
// Parameters:
//   - rc: RuntimeContext for logging and cancellation
//   - config: Agent configuration (see AgentConfig type)
//   - target: Where to deploy (cloudinit, docker, systemd)
//
// Returns:
//   - *DeploymentResult: Deployment outcome with details
//   - error: Any fatal error encountered
//
// Example:
//
//	config := agent.AgentConfig{
//	    NodeName:   "web-server-01",
//	    Datacenter: "dc1",
//	    Mode:       agent.ModeClient,
//	    RetryJoin:  []string{"10.0.1.10:8301", "10.0.1.11:8301"},
//	}
//	result, err := agent.DeployAgent(rc, config, agent.TargetDocker)
func DeployAgent(rc *eos_io.RuntimeContext, config AgentConfig, target DeploymentTarget) (*DeploymentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("ASSESS: Deploying Consul agent",
		zap.String("node_name", config.NodeName),
		zap.String("datacenter", config.Datacenter),
		zap.String("target", string(target)),
		zap.String("mode", string(config.Mode)))

	// ASSESS - Validate configuration
	if err := validateAgentConfig(config); err != nil {
		logger.Error("ASSESS FAILED: Invalid agent configuration",
			zap.Error(err))
		return &DeploymentResult{
			Success: false,
			Message: fmt.Sprintf("Invalid configuration: %v", err),
		}, fmt.Errorf("invalid agent configuration: %w", err)
	}

	// ASSESS - Discover environment if not fully configured
	envConfig, err := discoverEnvironment(rc, &config)
	if err != nil {
		logger.Warn("ASSESS: Environment discovery failed, using provided config",
			zap.Error(err))
		// Non-fatal - continue with provided config
	}

	// ASSESS - Initialize secret manager if Vault integration enabled
	var secretManager *secrets.SecretManager
	if config.VaultIntegration && envConfig != nil {
		secretManager, err = secrets.NewSecretManager(rc, envConfig)
		if err != nil {
			logger.Warn("ASSESS: Failed to initialize secret manager",
				zap.Error(err),
				zap.String("remediation", "Vault integration disabled for this deployment"))
			config.VaultIntegration = false
		} else {
			logger.Info("ASSESS: Secret manager initialized",
				zap.String("backend", "vault"))
		}
	}

	// Dry run check
	if config.DryRun {
		logger.Info("ASSESS: Dry-run mode enabled, skipping actual deployment")
		return &DeploymentResult{
			Success: true,
			Message: "Dry-run mode: Configuration validated successfully",
		}, nil
	}

	// INTERVENE - Deploy based on target platform
	logger.Info("INTERVENE: Deploying agent",
		zap.String("target", string(target)))

	var result *DeploymentResult
	switch target {
	case TargetCloudInit:
		result, err = deployViaCloudInit(rc, config, secretManager)
	case TargetDocker:
		result, err = deployViaDocker(rc, config, secretManager)
	case TargetSystemd:
		result, err = deployViaSystemd(rc, config, secretManager)
	default:
		err = fmt.Errorf("unsupported deployment target: %s", target)
	}

	if err != nil {
		logger.Error("INTERVENE FAILED: Agent deployment failed",
			zap.Error(err),
			zap.String("target", string(target)))
		return &DeploymentResult{
			Success: false,
			Message: fmt.Sprintf("Deployment failed: %v", err),
		}, fmt.Errorf("agent deployment failed: %w", err)
	}

	// Set deployment duration
	result.Duration = time.Since(startTime)

	// EVALUATE - Post-deployment verification (for Docker and systemd targets)
	if target == TargetDocker || target == TargetSystemd {
		logger.Info("EVALUATE: Verifying agent deployment")

		// Wait for agent to be ready (with timeout)
		if result.AgentAddress != "" {
			if err := WaitForAgentReady(rc, result.AgentAddress, 30*time.Second); err != nil {
				logger.Warn("EVALUATE: Agent health check failed",
					zap.Error(err),
					zap.String("remediation", "Agent deployed but may not be fully ready"))
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Health check timeout: %v", err))
			} else {
				logger.Info("EVALUATE: Agent is healthy and ready")
			}
		}

		// Register services if configured
		if len(config.Services) > 0 && result.AgentAddress != "" {
			logger.Info("EVALUATE: Registering services",
				zap.Int("count", len(config.Services)))

			if err := RegisterServices(rc, result.AgentAddress, config.Services); err != nil {
				logger.Warn("EVALUATE: Service registration failed",
					zap.Error(err))
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Service registration failed: %v", err))
			} else {
				logger.Info("EVALUATE: Services registered successfully",
					zap.Int("count", len(config.Services)))
			}
		}
	}

	// EVALUATE - Final success logging
	logger.Info("EVALUATE SUCCESS: Agent deployed successfully",
		zap.String("agent_id", result.AgentID),
		zap.String("address", result.AgentAddress),
		zap.Duration("duration", result.Duration),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// validateAgentConfig validates agent configuration for completeness and correctness
func validateAgentConfig(config AgentConfig) error {
	// Required fields
	if config.NodeName == "" {
		return fmt.Errorf("node_name is required")
	}

	if config.Datacenter == "" {
		return fmt.Errorf("datacenter is required")
	}

	// Mode validation
	if config.Mode == "" {
		config.Mode = ModeClient // Default to client mode
	}

	switch config.Mode {
	case ModeServer, ModeClient, ModeDev:
		// Valid modes
	default:
		return fmt.Errorf("invalid mode: %s (must be server, client, or dev)", config.Mode)
	}

	// Server mode validation
	if config.Mode == ModeServer {
		if config.BootstrapExpect < 1 {
			return fmt.Errorf("bootstrap_expect must be >= 1 for server mode")
		}
		if config.BootstrapExpect == 2 || config.BootstrapExpect == 4 {
			return fmt.Errorf("bootstrap_expect must be odd (1, 3, 5, 7...) for proper quorum, got %d", config.BootstrapExpect)
		}
	}

	// Client mode validation
	if config.Mode == ModeClient {
		if len(config.RetryJoin) == 0 {
			return fmt.Errorf("retry_join is required for client mode")
		}
	}

	// Log level validation
	if config.LogLevel != "" {
		validLogLevels := map[string]bool{
			"TRACE": true,
			"DEBUG": true,
			"INFO":  true,
			"WARN":  true,
			"ERROR": true,
		}
		if !validLogLevels[config.LogLevel] {
			return fmt.Errorf("invalid log_level: %s (must be TRACE, DEBUG, INFO, WARN, or ERROR)", config.LogLevel)
		}
	}

	return nil
}

// discoverEnvironment attempts to auto-discover environment configuration
// and enriches the agent config with discovered values
func discoverEnvironment(rc *eos_io.RuntimeContext, config *AgentConfig) (*environment.EnvironmentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Attempt environment discovery
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return nil, fmt.Errorf("environment discovery failed: %w", err)
	}

	logger.Info("ASSESS: Environment discovered",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.String("node_role", envConfig.NodeRole))

	// Enrich config with discovered values (only if not already set)
	if config.Environment == "" {
		config.Environment = envConfig.Environment
	}

	if config.Datacenter == "" {
		config.Datacenter = envConfig.Datacenter
	}

	// For client mode, populate retry_join from discovered cluster nodes
	if config.Mode == ModeClient && len(config.RetryJoin) == 0 {
		config.RetryJoin = envConfig.ClusterNodes
		logger.Info("ASSESS: Populated retry_join from environment",
			zap.Strings("servers", config.RetryJoin))
	}

	return envConfig, nil
}

// deployViaCloudInit generates cloud-init configuration for agent deployment
// This is used for KVM guests and cloud VMs
func deployViaCloudInit(rc *eos_io.RuntimeContext, config AgentConfig, secretManager *secrets.SecretManager) (*DeploymentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("INTERVENE: Generating cloud-init for Consul agent")

	// Generate cloud-init YAML
	cloudInit, err := GenerateCloudInit(rc, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cloud-init: %w", err)
	}

	logger.Info("INTERVENE: Cloud-init generated successfully",
		zap.Int("size_bytes", len(cloudInit)))

	// For cloud-init, we return the configuration
	// The actual deployment happens when the VM boots
	return &DeploymentResult{
		Success:    true,
		AgentID:    config.NodeName,
		ConfigPath: "", // Set by caller after writing to disk
		Message:    "Cloud-init generated successfully (deployment will occur on VM boot)",
		Warnings:   []string{},
	}, nil
}

// deployViaDocker deploys Consul agent as a Docker Compose sidecar
func deployViaDocker(rc *eos_io.RuntimeContext, config AgentConfig, secretManager *secrets.SecretManager) (*DeploymentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("INTERVENE: Deploying Consul agent via Docker")

	// Generate Docker Compose service definition
	dockerService, err := GenerateDockerComposeSidecar(rc, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Docker Compose sidecar: %w", err)
	}

	logger.Info("INTERVENE: Docker Compose sidecar generated",
		zap.String("service_name", dockerService["container_name"].(string)))

	// TODO: Implement actual Docker deployment
	// This will be implemented in docker.go
	// For now, return the service definition

	return &DeploymentResult{
		Success:      true,
		AgentID:      config.NodeName,
		AgentAddress: shared.GetConsulAddress(),
		Message:      "Docker Compose sidecar configuration generated (deployment not yet implemented)",
		Warnings:     []string{"Docker deployment implementation pending"},
	}, nil
}

// deployViaSystemd deploys Consul agent as a native systemd service
func deployViaSystemd(rc *eos_io.RuntimeContext, config AgentConfig, secretManager *secrets.SecretManager) (*DeploymentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("INTERVENE: Deploying Consul agent via systemd")

	// TODO: Implement systemd deployment
	// This will be implemented in systemd.go (Phase 3)

	return &DeploymentResult{
		Success:  false,
		AgentID:  config.NodeName,
		Message:  "Systemd deployment not yet implemented (planned for Phase 3)",
		Warnings: []string{"Use TargetCloudInit or TargetDocker for now"},
	}, fmt.Errorf("systemd deployment not implemented")
}
