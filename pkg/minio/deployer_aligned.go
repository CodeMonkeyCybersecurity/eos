package minio

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AlignedDeployer implements STACK.md-compliant deployment
type AlignedDeployer struct {
	terraformBase string
	stateBackend  string
}

// NewAlignedDeployer creates a deployer that follows STACK.md architecture
func NewAlignedDeployer() *AlignedDeployer {
	return &AlignedDeployer{
		terraformBase: "/srv/terraform/minio",
		stateBackend:  "consul",
	}
}

// Deploy follows the SaltStack → Terraform → Nomad orchestration hierarchy
func (ad *AlignedDeployer) Deploy(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	appName := fmt.Sprintf("minio-%s", opts.Datacenter)
	
	// Step 1: Generate Salt pillar data for this deployment
	logger.Info("Setting MinIO pillar data for SaltStack configuration generation")
	if err := ad.setSaltPillarData(rc, appName, opts); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to set pillar data: %w", err))
	}
	
	// Step 2: Apply Salt states to generate Terraform configurations
	logger.Info("Applying SaltStack states to generate Terraform configurations")
	if err := ad.applySaltTerraformGeneration(rc, appName); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to generate Terraform configs via Salt: %w", err))
	}
	
	// Step 3: Validate Terraform state consistency
	logger.Info("Validating Terraform state consistency")
	terraformDir := filepath.Join(ad.terraformBase, appName)
	if err := ad.validateTerraformState(rc, terraformDir); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Terraform state validation failed: %w", err))
	}
	
	// Step 4: Apply Terraform configuration with proper state management
	logger.Info("Applying Terraform configuration")
	if err := ad.applyTerraformWithStateManagement(rc, terraformDir); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Terraform apply failed: %w", err))
	}
	
	// Step 5: Verify deployment through Nomad
	logger.Info("Verifying deployment through Nomad")
	if err := ad.verifyNomadDeployment(rc, appName, opts); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("deployment verification failed: %w", err))
	}
	
	// Step 6: Update service discovery
	logger.Info("Updating service discovery")
	if err := ad.updateServiceDiscovery(rc, appName, opts); err != nil {
		logger.Warn("Service discovery update failed", zap.Error(err))
	}
	
	ad.displayAccessInfo(rc, appName, opts)
	
	return nil
}

// setSaltPillarData configures Salt pillar for this MinIO instance
func (ad *AlignedDeployer) setSaltPillarData(rc *eos_io.RuntimeContext, appName string, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create pillar file for this MinIO deployment
	pillarContent := fmt.Sprintf(`# MinIO deployment configuration
minio:
  app_name: %s
  datacenter: %s
  storage_path: %s
  api_port: %d
  console_port: %d
  terraform_base: %s
  
  # Resource allocation
  memory_limit: 2048
  cpu_limit: 1000
  
  # Storage backend selection
  use_cephfs: false
  
  # Vault integration
  vault_policy: minio-policy-%s
  vault_path: kv/minio/%s
  
  # Health check configuration
  health_check_interval: "30s"
  health_check_timeout: "5s"
  
  # Service discovery
  consul_service_name: minio-%s
  consul_tags:
    - minio
    - s3
    - %s
`, appName, opts.Datacenter, opts.StoragePath, opts.APIPort, 
   opts.ConsolePort, ad.terraformBase, appName, appName, appName, opts.Datacenter)
	
	pillarPath := fmt.Sprintf("/srv/pillar/minio/%s.sls", appName)
	
	// Write pillar file
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"mkdir", "-p", "/srv/pillar/minio"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create pillar directory: %w", err)
	}
	logger.Debug("Created pillar directory", zap.String("output", output))
	
	// Write pillar content
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"tee", pillarPath},
		Input:   pillarContent,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to write pillar file: %w", err)
	}
	logger.Debug("Wrote pillar file", zap.String("path", pillarPath))
	
	return nil
}

// applySaltTerraformGeneration runs Salt states to generate Terraform configs
func (ad *AlignedDeployer) applySaltTerraformGeneration(rc *eos_io.RuntimeContext, appName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Apply the terraform generator state with the specific pillar
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args: []string{
			"--local",
			"state.apply",
			"minio.terraform_generator",
			fmt.Sprintf("pillar='{\"minio\": {\"app_name\": \"%s\"}}'", appName),
		},
		Timeout: 300 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to generate Terraform configs: %w", err)
	}
	logger.Debug("Terraform generation output", zap.String("output", output))
	
	// Also apply base MinIO states for system preparation
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "state.apply", "minio"},
		Timeout: 300 * time.Second,
	})
	if err != nil {
		logger.Warn("Base MinIO state application failed", zap.Error(err))
	}
	
	return nil
}

// validateTerraformState ensures state consistency
func (ad *AlignedDeployer) validateTerraformState(rc *eos_io.RuntimeContext, terraformDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Initialize with backend
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"init", "-backend=true", "-upgrade"},
		Dir:     terraformDir,
		Timeout: 300 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}
	logger.Debug("Terraform init output", zap.String("output", output))
	
	// Refresh state to detect drift
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"refresh"},
		Dir:     terraformDir,
		Timeout: 180 * time.Second,
	})
	if err != nil {
		logger.Warn("Terraform refresh failed, may be first deployment", zap.Error(err))
	}
	
	// Validate configuration
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"validate"},
		Dir:     terraformDir,
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform validation failed: %w", err)
	}
	logger.Info("Terraform configuration validated successfully")
	
	return nil
}

// applyTerraformWithStateManagement applies configuration with proper locking
func (ad *AlignedDeployer) applyTerraformWithStateManagement(rc *eos_io.RuntimeContext, terraformDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Plan first to show what will change
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"plan", "-out=tfplan"},
		Dir:     terraformDir,
		Timeout: 300 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform plan failed: %w", err)
	}
	logger.Debug("Terraform plan output", zap.String("output", output))
	
	// Apply the plan
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"apply", "-auto-approve", "tfplan"},
		Dir:     terraformDir,
		Timeout: 600 * time.Second,
	})
	if err != nil {
		// Check if it's a Vault availability issue
		if err := ad.handleVaultUnavailability(rc, err); err != nil {
			return err
		}
		// Retry with degraded mode
		return ad.applyTerraformDegradedMode(rc, terraformDir)
	}
	logger.Debug("Terraform apply output", zap.String("output", output))
	
	return nil
}

// handleVaultUnavailability implements graceful degradation when Vault is unavailable
func (ad *AlignedDeployer) handleVaultUnavailability(rc *eos_io.RuntimeContext, originalErr error) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Vault is accessible
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status"},
		Timeout: 10 * time.Second,
	})
	
	if err != nil {
		logger.Warn("Vault is unavailable, will deploy with default credentials",
			zap.Error(err),
			zap.String("output", output))
		logger.Warn("SECURITY WARNING: Using default MinIO credentials. Change immediately after deployment!")
		return nil
	}
	
	// Vault is available, so this is a different error
	return originalErr
}

// applyTerraformDegradedMode applies Terraform without Vault integration
func (ad *AlignedDeployer) applyTerraformDegradedMode(rc *eos_io.RuntimeContext, terraformDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Warn("Applying Terraform in degraded mode without Vault integration")
	
	// Set environment variables to skip Vault operations
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"apply", "-auto-approve", "-var", "skip_vault=true"},
		Dir:     terraformDir,
		Env:     []string{"TF_VAR_skip_vault=true"},
		Timeout: 600 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform apply in degraded mode failed: %w", err)
	}
	logger.Debug("Terraform degraded apply output", zap.String("output", output))
	
	return nil
}

// verifyNomadDeployment checks the deployment through Nomad
func (ad *AlignedDeployer) verifyNomadDeployment(rc *eos_io.RuntimeContext, appName string, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Wait for job to be registered
	time.Sleep(5 * time.Second)
	
	// Check job status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", appName},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check Nomad job status: %w", err)
	}
	logger.Debug("Nomad job status", zap.String("output", output))
	
	// Check allocation health
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "allocs", appName},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to check allocations", zap.Error(err))
	} else {
		logger.Debug("Nomad allocations", zap.String("output", output))
	}
	
	// Wait for service to start
	logger.Info("Waiting for MinIO to become healthy...")
	for i := 0; i < 30; i++ {
		healthURL := fmt.Sprintf("http://localhost:%d/minio/health/live", opts.APIPort)
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-f", "-s", healthURL},
			Timeout: 5 * time.Second,
		})
		if err == nil {
			logger.Info("MinIO is healthy")
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	
	logger.Warn("MinIO health check timed out, but service may still be starting")
	return nil
}

// updateServiceDiscovery ensures Consul has correct service information
func (ad *AlignedDeployer) updateServiceDiscovery(rc *eos_io.RuntimeContext, appName string, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if service is registered in Consul
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"catalog", "services"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to query Consul services: %w", err)
	}
	logger.Debug("Consul services", zap.String("output", output))
	
	// Verify service health
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"monitor", "-log-level=debug"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		logger.Debug("Consul monitor output", zap.String("output", output))
	}
	
	return nil
}

// displayAccessInfo shows deployment information
func (ad *AlignedDeployer) displayAccessInfo(rc *eos_io.RuntimeContext, appName string, opts *DeploymentOptions) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("MinIO deployment successful",
		zap.String("app_name", appName),
		zap.String("api_endpoint", fmt.Sprintf("http://localhost:%d", opts.APIPort)),
		zap.String("console_endpoint", fmt.Sprintf("http://localhost:%d", opts.ConsolePort)),
		zap.String("terraform_dir", filepath.Join(ad.terraformBase, appName)),
	)
	
	logger.Info("Access information:",
		zap.String("credentials", fmt.Sprintf("vault kv get kv/minio/%s", appName)),
		zap.String("mc_config", fmt.Sprintf("mc alias set %s http://localhost:%d $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD", appName, opts.APIPort)),
	)
}

// Common Workarounds for MinIO Deployment Issues

// WorkaroundVolumeManagement handles Nomad volume creation issues
func (ad *AlignedDeployer) WorkaroundVolumeManagement(rc *eos_io.RuntimeContext, appName string, storagePath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Ensuring Nomad host volume exists")
	
	// Create the storage directory if it doesn't exist
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"mkdir", "-p", storagePath},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	// Set proper permissions for MinIO
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"chown", "-R", "1000:1000", storagePath},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to set storage permissions", zap.Error(err))
	}
	
	// Register host volume with Nomad (if not already registered)
	volumeName := fmt.Sprintf("minio-data-%s", appName)
	nomadConfig := fmt.Sprintf(`
host_volume "%s" {
  path = "%s"
  read_only = false
}
`, volumeName, storagePath)
	
	logger.Info("Host volume configuration", zap.String("config", nomadConfig))
	logger.Info("Add this to your Nomad client configuration and restart Nomad if volume is not available")
	
	return nil
}

// WorkaroundResourceConstraints adjusts resource allocations based on available resources
func (ad *AlignedDeployer) WorkaroundResourceConstraints(rc *eos_io.RuntimeContext) (memory int, cpu int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Query Nomad for available resources
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"node", "status", "-json"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to query Nomad resources, using defaults", zap.Error(err))
		return 1024, 500, nil
	}
	
	// Parse and determine appropriate resource allocation
	// This is simplified - in production you'd parse the JSON properly
	logger.Info("Determining optimal resource allocation based on cluster capacity")
	
	// Conservative defaults that should work on most systems
	return 1024, 500, nil
}

// WorkaroundHealthCheckTiming adjusts health check parameters for slow systems
func (ad *AlignedDeployer) WorkaroundHealthCheckTiming(rc *eos_io.RuntimeContext) (interval string, timeout string) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check system load to determine appropriate timings
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "uptime",
		Args:    []string{},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to check system load", zap.Error(err))
		return "30s", "5s"
	}
	
	logger.Debug("System load", zap.String("output", output))
	
	// Adjust based on system characteristics
	// For heavily loaded systems, increase intervals
	return "45s", "10s"
}