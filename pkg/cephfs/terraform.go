package cephfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployTerraform deploys CephFS infrastructure using Terraform
func DeployTerraform(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if Terraform is available and prerequisites are met
	logger.Info("Assessing Terraform prerequisites for CephFS deployment")
	if err := assessTerraformPrerequisites(rc, config); err != nil {
		return fmt.Errorf("failed to assess Terraform prerequisites: %w", err)
	}

	// INTERVENE: Apply Terraform configuration
	logger.Info("Applying Terraform configuration for CephFS")
	if err := applyTerraformConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to apply Terraform configuration: %w", err)
	}

	// EVALUATE: Verify Terraform deployment
	logger.Info("Verifying Terraform deployment")
	if err := verifyTerraformDeployment(rc, config); err != nil {
		return fmt.Errorf("failed to verify Terraform deployment: %w", err)
	}

	logger.Info("Terraform deployment completed successfully")
	return nil
}

// assessTerraformPrerequisites checks if Terraform is available and prerequisites are met
func assessTerraformPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if terraform is available
	logger.Debug("Checking for terraform executable")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"terraform"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("terraform not found: please install Terraform first"))
	}
	logger.Debug("terraform found", zap.String("path", strings.TrimSpace(output)))

	// Check if Terraform configuration exists
	configPath := GetTerraformCephConfigPath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("terraform configuration not found at %s: run SaltStack generation first", configPath))
	}

	// Check SSH connectivity to admin host
	logger.Debug("Checking SSH connectivity to admin host")
	if err := checkSSHConnectivity(rc, config); err != nil {
		return fmt.Errorf("failed SSH connectivity check: %w", err)
	}

	// Check if cephadm is available on admin host
	logger.Debug("Checking for cephadm on admin host")
	if err := checkCephadmAvailability(rc, config); err != nil {
		return fmt.Errorf("cephadm availability check failed: %w", err)
	}

	logger.Debug("Terraform prerequisites satisfied")
	return nil
}

// checkSSHConnectivity checks if we can connect to the admin host via SSH
func checkSSHConnectivity(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Testing SSH connection",
		zap.String("host", config.AdminHost),
		zap.String("user", config.SSHUser))

	// Test SSH connection with a simple command
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"echo", "SSH connection test successful",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("SSH connection test failed: %w", err)
	}

	if !strings.Contains(output, "SSH connection test successful") {
		return fmt.Errorf("SSH connection test failed: unexpected output: %s", output)
	}

	logger.Debug("SSH connectivity verified")
	return nil
}

// checkCephadmAvailability checks if cephadm is available on the admin host
func checkCephadmAvailability(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking cephadm availability on admin host")

	// Check if cephadm is available on the remote host
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"which", "cephadm",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("cephadm not found on admin host %s: %w", config.AdminHost, err)
	}

	cephadmPath := strings.TrimSpace(output)
	if cephadmPath == "" {
		return fmt.Errorf("cephadm not found in PATH on admin host %s", config.AdminHost)
	}

	logger.Debug("cephadm found on admin host",
		zap.String("path", cephadmPath),
		zap.String("host", config.AdminHost))

	return nil
}

// applyTerraformConfiguration applies the Terraform configuration
func applyTerraformConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	terraformDir := TerraformCephDir

	// Initialize Terraform if needed
	if err := initializeTerraform(rc, terraformDir); err != nil {
		return fmt.Errorf("failed to initialize Terraform: %w", err)
	}

	// Plan Terraform changes
	planFile := filepath.Join(terraformDir, TerraformPlanFile)
	if err := planTerraformChanges(rc, terraformDir, planFile, config); err != nil {
		return fmt.Errorf("failed to plan Terraform changes: %w", err)
	}

	// Apply Terraform changes
	if err := applyTerraformPlan(rc, terraformDir, planFile); err != nil {
		return fmt.Errorf("failed to apply Terraform plan: %w", err)
	}

	logger.Info("Terraform configuration applied successfully")
	return nil
}

// initializeTerraform initializes the Terraform working directory
func initializeTerraform(rc *eos_io.RuntimeContext, terraformDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Initializing Terraform", zap.String("dir", terraformDir))

	// Check if already initialized
	if _, err := os.Stat(filepath.Join(terraformDir, ".terraform")); err == nil {
		logger.Debug("Terraform already initialized")
		return nil
	}

	// Run terraform init
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"init"},
		Dir:     terraformDir,
		Timeout: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	if !strings.Contains(output, "Terraform has been successfully initialized") {
		return fmt.Errorf("terraform init did not complete successfully: %s", output)
	}

	logger.Debug("Terraform initialized successfully")
	return nil
}

// planTerraformChanges creates a Terraform plan
func planTerraformChanges(rc *eos_io.RuntimeContext, terraformDir, planFile string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating Terraform plan",
		zap.String("dir", terraformDir),
		zap.String("planFile", planFile))

	// Prepare Terraform variables
	args := []string{
		"plan",
		"-out=" + planFile,
		"-var", fmt.Sprintf("cluster_fsid=%s", config.ClusterFSID),
		"-var", fmt.Sprintf("admin_host=%s", config.AdminHost),
		"-var", fmt.Sprintf("ssh_user=%s", config.SSHUser),
		"-var", fmt.Sprintf("ceph_image=%s", config.CephImage),
		"-var", fmt.Sprintf("public_network=%s", config.PublicNetwork),
		"-var", fmt.Sprintf("cluster_network=%s", config.ClusterNetwork),
		"-var", fmt.Sprintf("objectstore=%s", config.GetObjectStore()),
	}

	// Add OSD devices if specified
	if len(config.OSDDevices) > 0 {
		deviceList := "[\"" + strings.Join(config.OSDDevices, "\",\"") + "\"]"
		args = append(args, "-var", fmt.Sprintf("osd_devices=%s", deviceList))
	}

	// Run terraform plan
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    args,
		Dir:     terraformDir,
		Timeout: 10 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	if strings.Contains(output, "Error:") {
		return fmt.Errorf("terraform plan contains errors: %s", output)
	}

	logger.Debug("Terraform plan created successfully")
	return nil
}

// applyTerraformPlan applies the Terraform plan
func applyTerraformPlan(rc *eos_io.RuntimeContext, terraformDir, planFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Applying Terraform plan",
		zap.String("dir", terraformDir),
		zap.String("planFile", planFile))

	// Run terraform apply
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"apply", "-auto-approve", planFile},
		Dir:     terraformDir,
		Timeout: DefaultDeploymentTimeout,
	})
	if err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	if strings.Contains(output, "Error:") {
		return fmt.Errorf("terraform apply contains errors: %s", output)
	}

	if !strings.Contains(output, "Apply complete!") {
		return fmt.Errorf("terraform apply did not complete successfully: %s", output)
	}

	logger.Info("Terraform plan applied successfully")
	return nil
}

// verifyTerraformDeployment verifies the Terraform deployment was successful
func verifyTerraformDeployment(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	terraformDir := TerraformCephDir

	// Check Terraform state
	logger.Debug("Checking Terraform state")
	if err := checkTerraformState(rc, terraformDir); err != nil {
		return fmt.Errorf("terraform state check failed: %w", err)
	}

	// Verify OSD spec was applied
	logger.Debug("Verifying OSD spec application")
	if err := verifyOSDSpecApplication(rc, config); err != nil {
		return fmt.Errorf("OSD spec verification failed: %w", err)
	}

	// Verify cluster network configuration
	logger.Debug("Verifying cluster network configuration")
	if err := verifyNetworkConfiguration(rc, config); err != nil {
		return fmt.Errorf("network configuration verification failed: %w", err)
	}

	logger.Debug("Terraform deployment verification completed")
	return nil
}

// checkTerraformState checks the Terraform state file
func checkTerraformState(rc *eos_io.RuntimeContext, terraformDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if state file exists
	stateFile := filepath.Join(terraformDir, TerraformStateFile)
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return fmt.Errorf("terraform state file not found: %s", stateFile)
	}

	// Run terraform show to validate state
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"show", "-json"},
		Dir:     terraformDir,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to read Terraform state: %w", err)
	}

	if !strings.Contains(output, "null_resource.apply_ceph_spec") {
		return fmt.Errorf("expected Terraform resources not found in state")
	}

	logger.Debug("Terraform state validation passed")
	return nil
}

// verifyOSDSpecApplication verifies that the OSD spec was applied on the admin host
func verifyOSDSpecApplication(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying OSD spec application on admin host")

	// Check if OSD spec was applied via ceph orch ls
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "orch", "ls", "--service-type", "osd", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check OSD services: %w", err)
	}

	if !strings.Contains(output, "all-available-devices") {
		return fmt.Errorf("OSD spec 'all-available-devices' not found in orchestrator services")
	}

	logger.Debug("OSD spec application verified")
	return nil
}

// verifyNetworkConfiguration verifies that network configuration was applied
func verifyNetworkConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying network configuration")

	// Check public network configuration
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "get", "mon", "public_network",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check public network configuration: %w", err)
	}

	if !strings.Contains(output, config.PublicNetwork) {
		return fmt.Errorf("public network configuration mismatch: expected %s, got %s", config.PublicNetwork, output)
	}

	// Check cluster network configuration
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "get", "mon", "cluster_network",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check cluster network configuration: %w", err)
	}

	if !strings.Contains(output, config.ClusterNetwork) {
		return fmt.Errorf("cluster network configuration mismatch: expected %s, got %s", config.ClusterNetwork, output)
	}

	logger.Debug("Network configuration verified")
	return nil
}

// GetTerraformOutputs retrieves Terraform outputs
func GetTerraformOutputs(rc *eos_io.RuntimeContext) (map[string]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	terraformDir := TerraformCephDir

	logger.Debug("Getting Terraform outputs", zap.String("dir", terraformDir))

	// Run terraform output
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"output", "-json"},
		Dir:     terraformDir,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform outputs: %w", err)
	}

	// Parse the JSON output (simplified parsing)
	outputs := make(map[string]string)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "cluster_fsid") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				value := strings.Trim(strings.Trim(parts[1], " "), "\"")
				outputs["cluster_fsid"] = value
			}
		}
		if strings.Contains(line, "admin_host") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				value := strings.Trim(strings.Trim(parts[1], " "), "\"")
				outputs["admin_host"] = value
			}
		}
	}

	logger.Debug("Retrieved Terraform outputs", zap.Any("outputs", outputs))
	return outputs, nil
}

// DestroyTerraformDeployment destroys the Terraform deployment
func DestroyTerraformDeployment(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	terraformDir := TerraformCephDir

	logger.Warn("Destroying Terraform deployment", zap.String("dir", terraformDir))

	// Run terraform destroy
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"destroy", "-auto-approve"},
		Dir:     terraformDir,
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	if strings.Contains(output, "Error:") {
		return fmt.Errorf("terraform destroy contains errors: %s", output)
	}

	logger.Info("Terraform deployment destroyed successfully")
	return nil
}
