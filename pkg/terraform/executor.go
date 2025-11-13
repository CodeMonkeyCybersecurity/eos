// Package terraform provides Terraform integration for Eos infrastructure management
package terraform

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Executor manages Terraform operations
type Executor struct {
	consulClient *api.Client
	vaultClient  *vault.Client
	workspaceDir string
}

// NewExecutor creates a new Terraform executor
func NewExecutor(workspaceDir string) (*Executor, error) {
	// Initialize Consul client
	consulConfig := api.DefaultConfig()
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Initialize Vault client
	logger := zap.NewNop() // TODO: Use proper logger from context
	vaultAddr := shared.GetVaultAddrWithEnv()
	vaultClient, err := vault.NewClient(vaultAddr, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	return &Executor{
		consulClient: consulClient,
		vaultClient:  vaultClient,
		workspaceDir: workspaceDir,
	}, nil
}

// InitWorkspace initializes a Terraform workspace for a component
func (e *Executor) InitWorkspace(rc *eos_io.RuntimeContext, component, environment string, backendConfig *BackendConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Terraform workspace",
		zap.String("component", component),
		zap.String("environment", environment))

	// ASSESS - Check if we can initialize the workspace
	if _, err := exec.LookPath("terraform"); err != nil {
		return eos_err.NewUserError("terraform binary not found in PATH")
	}

	workspace := e.getWorkspace(component, environment)

	// Create workspace directory
	if err := os.MkdirAll(workspace.Path, shared.ServiceDirPerm); err != nil {
		if os.IsPermission(err) {
			return eos_err.NewUserError("insufficient permissions to create workspace directory")
		}
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// INTERVENE - Generate and write backend configuration
	if backendConfig != nil {
		backendTF := e.generateBackendConfig(rc, backendConfig)
		backendPath := filepath.Join(workspace.Path, "backend.tf")
		if err := os.WriteFile(backendPath, []byte(backendTF), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("failed to write backend configuration: %w", err)
		}
	}

	// Acquire distributed lock
	lock, err := e.acquireLock(rc, component, environment)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer e.releaseLock(rc, lock)

	// Run terraform init
	envVars, err := e.getProviderCredentials(rc, component)
	if err != nil {
		return fmt.Errorf("failed to get provider credentials: %w", err)
	}

	// Set environment variables in current process for terraform
	for k, v := range envVars {
		_ = os.Setenv(k, v)
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"init", "-reconfigure"},
		Dir:     workspace.Path,
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// EVALUATE - Verify initialization succeeded
	initCheckPath := filepath.Join(workspace.Path, ".terraform")
	if _, err := os.Stat(initCheckPath); os.IsNotExist(err) {
		return fmt.Errorf("terraform initialization verification failed - .terraform directory not created")
	}

	// Store workspace metadata in Consul
	if err := e.storeWorkspaceMetadata(rc, workspace, "initialized"); err != nil {
		logger.Warn("Failed to store workspace metadata", zap.Error(err))
	}

	logger.Info("Terraform workspace initialized successfully",
		zap.String("output", output))
	return nil
}

// Plan generates a Terraform execution plan
func (e *Executor) Plan(rc *eos_io.RuntimeContext, component, environment string, variables map[string]any, destroy bool) (*PlanResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Terraform plan",
		zap.String("component", component),
		zap.String("environment", environment),
		zap.Bool("destroy", destroy))

	// ASSESS - Check prerequisites
	workspace := e.getWorkspace(component, environment)
	if _, err := os.Stat(workspace.Path); os.IsNotExist(err) {
		return nil, eos_err.NewUserError("workspace not initialized - run init first")
	}

	// Generate tfvars file
	tfvars := e.generateTfvars(rc, component, environment, variables)
	tfvarsPath := filepath.Join(workspace.Path, "terraform.tfvars.json")
	tfvarsData, err := json.MarshalIndent(tfvars, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tfvars: %w", err)
	}
	if err := os.WriteFile(tfvarsPath, tfvarsData, shared.ConfigFilePerm); err != nil {
		return nil, fmt.Errorf("failed to write tfvars: %w", err)
	}

	// Acquire lock
	lock, err := e.acquireLock(rc, component, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer e.releaseLock(rc, lock)

	// INTERVENE - Run terraform plan
	args := []string{"plan", "-detailed-exitcode", "-out=tfplan"}
	if destroy {
		args = append(args, "-destroy")
	}

	envVars, err := e.getProviderCredentials(rc, component)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider credentials: %w", err)
	}

	// Set environment variables in current process for terraform
	for k, v := range envVars {
		_ = os.Setenv(k, v)
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    args,
		Dir:     workspace.Path,
		Capture: true,
	})

	// Parse exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			if exitCode != 2 { // 2 is expected when changes are present
				return &PlanResult{
					Success: false,
					Error:   output,
				}, nil
			}
		} else {
			return &PlanResult{
				Success: false,
				Error:   output,
			}, nil
		}
	}

	// EVALUATE - Parse plan output
	planJSON, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"show", "-json", "tfplan"},
		Dir:     workspace.Path,
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w", err)
	}

	var planData map[string]any
	if err := json.Unmarshal([]byte(planJSON), &planData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plan JSON: %w", err)
	}

	result := &PlanResult{
		Success:        true,
		ChangesPresent: exitCode == 2,
		PlanFile:       "tfplan",
	}

	// Extract resource changes
	if resourceChanges, ok := planData["resource_changes"].([]any); ok {
		for _, change := range resourceChanges {
			if changeMap, ok := change.(map[string]any); ok {
				rc := ResourceChange{
					Address: getString(changeMap, "address"),
					Type:    getString(changeMap, "type"),
					Name:    getString(changeMap, "name"),
				}
				if actions, ok := changeMap["change"].(map[string]any)["actions"].([]any); ok {
					for _, action := range actions {
						if actionStr, ok := action.(string); ok {
							rc.Action = append(rc.Action, actionStr)
						}
					}
				}
				result.ResourceChanges = append(result.ResourceChanges, rc)
			}
		}
	}

	logger.Info("Terraform plan completed",
		zap.Bool("changes_present", result.ChangesPresent),
		zap.Int("resource_changes", len(result.ResourceChanges)))

	return result, nil
}

// Apply applies Terraform changes
func (e *Executor) Apply(rc *eos_io.RuntimeContext, component, environment string, planFile string, autoApprove bool) (*ApplyResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying Terraform changes",
		zap.String("component", component),
		zap.String("environment", environment))

	// ASSESS - Verify preconditions
	if err := e.verifyPreconditions(rc, component, environment); err != nil {
		return nil, fmt.Errorf("preconditions not met: %w", err)
	}

	workspace := e.getWorkspace(component, environment)

	// Take pre-apply snapshot
	snapshotID, err := e.createStateSnapshot(rc, component, environment)
	if err != nil {
		logger.Warn("Failed to create state snapshot", zap.Error(err))
	}

	// Acquire extended lock for apply operation
	lock, err := e.acquireLock(rc, component, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer e.releaseLock(rc, lock)

	// INTERVENE - Apply changes
	args := []string{"apply"}
	if planFile != "" {
		args = append(args, planFile)
	} else if autoApprove {
		args = append(args, "-auto-approve")
	} else {
		return nil, eos_err.NewUserError("must provide plan_file or set auto_approve=true")
	}

	envVars, err := e.getProviderCredentials(rc, component)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider credentials: %w", err)
	}

	// Set environment variables in current process for terraform
	for k, v := range envVars {
		_ = os.Setenv(k, v)
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    args,
		Dir:     workspace.Path,
		Capture: true,
		Timeout: 30 * time.Minute,
	})

	if err != nil {
		// Attempt rollback on failure
		if snapshotID != "" && autoApprove {
			rollbackResult := e.rollbackToSnapshot(rc, component, environment, snapshotID)
			return &ApplyResult{
				Success:    false,
				Error:      output,
				SnapshotID: snapshotID,
				Rollback:   rollbackResult,
			}, nil
		}
		return &ApplyResult{
			Success:    false,
			Error:      output,
			SnapshotID: snapshotID,
		}, nil
	}

	// EVALUATE - Get outputs
	outputs, err := e.GetOutputs(rc, component, environment)
	if err != nil {
		logger.Warn("Failed to get outputs", zap.Error(err))
	}

	// Store outputs in Consul
	if err := e.storeOutputsInConsul(rc, component, environment, outputs); err != nil {
		logger.Warn("Failed to store outputs in Consul", zap.Error(err))
	}

	// Update component metadata
	if err := e.updateComponentMetadata(rc, component, environment, "applied", snapshotID); err != nil {
		logger.Warn("Failed to update component metadata", zap.Error(err))
	}

	// Run post-apply hooks
	if err := e.runPostApplyHooks(rc, component, environment, outputs); err != nil {
		logger.Warn("Failed to run post-apply hooks", zap.Error(err))
	}

	result := &ApplyResult{
		Success:    true,
		Outputs:    outputs,
		SnapshotID: snapshotID,
	}

	logger.Info("Terraform apply completed successfully",
		zap.Int("outputs", len(outputs)))

	return result, nil
}

// GetOutputs retrieves Terraform outputs
func (e *Executor) GetOutputs(rc *eos_io.RuntimeContext, component, environment string) (map[string]Output, error) {
	workspace := e.getWorkspace(component, environment)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"output", "-json"},
		Dir:     workspace.Path,
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get outputs: %w", err)
	}

	var outputData map[string]map[string]any
	if err := json.Unmarshal([]byte(output), &outputData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal outputs: %w", err)
	}

	outputs := make(map[string]Output)
	for name, data := range outputData {
		outputs[name] = Output{
			Value:     data["value"],
			Type:      getString(data, "type"),
			Sensitive: getBool(data, "sensitive"),
		}
	}

	return outputs, nil
}

// Destroy destroys Terraform-managed infrastructure
func (e *Executor) Destroy(rc *eos_io.RuntimeContext, component, environment string, autoApprove bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Destroying Terraform infrastructure",
		zap.String("component", component),
		zap.String("environment", environment))

	// Generate destroy plan first
	planResult, err := e.Plan(rc, component, environment, nil, true)
	if err != nil {
		return fmt.Errorf("failed to generate destroy plan: %w", err)
	}

	if !planResult.ChangesPresent {
		logger.Info("No resources to destroy")
		return nil
	}

	// Apply destroy plan
	applyResult, err := e.Apply(rc, component, environment, planResult.PlanFile, autoApprove)
	if err != nil {
		return fmt.Errorf("failed to apply destroy plan: %w", err)
	}

	if !applyResult.Success {
		return fmt.Errorf("destroy operation failed: %s", applyResult.Error)
	}

	// Clean up Consul entries
	if err := e.cleanupConsulEntries(rc, component, environment); err != nil {
		logger.Warn("Failed to cleanup Consul entries", zap.Error(err))
	}

	logger.Info("Infrastructure destroyed successfully")
	return nil
}

// GetResources gets the list of Terraform-managed resources
func (e *Executor) GetResources(rc *eos_io.RuntimeContext, component, environment string) (*ResourceList, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting Terraform resources",
		zap.String("component", component),
		zap.String("environment", environment))

	workspace := e.getWorkspace(component, environment)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"state", "list"},
		Dir:     workspace.Path,
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	// Parse resource list
	resources := strings.Split(strings.TrimSpace(output), "\n")

	// Filter out empty lines
	var filtered []string
	for _, r := range resources {
		if r != "" {
			filtered = append(filtered, r)
		}
	}

	return &ResourceList{
		Resources: filtered,
		Count:     len(filtered),
	}, nil
}

// GetState gets the state of a specific resource
func (e *Executor) GetState(rc *eos_io.RuntimeContext, component, environment, resource string) (*ResourceState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting resource state",
		zap.String("component", component),
		zap.String("environment", environment),
		zap.String("resource", resource))

	workspace := e.getWorkspace(component, environment)

	args := []string{"state", "show"}
	if resource != "" {
		args = append(args, resource)
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    args,
		Dir:     workspace.Path,
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get resource state: %w", err)
	}

	return &ResourceState{
		Resource: resource,
		State:    output,
	}, nil
}

// Helper methods

func (e *Executor) getWorkspace(component, environment string) *Workspace {
	return &Workspace{
		Component:   component,
		Environment: environment,
		Path:        filepath.Join(e.workspaceDir, environment, component),
	}
}

func (e *Executor) generateBackendConfig(_ *eos_io.RuntimeContext, config *BackendConfig) string {
	var sb strings.Builder
	sb.WriteString("terraform {\n")
	sb.WriteString(fmt.Sprintf("  backend \"%s\" {\n", config.Type))
	for key, value := range config.Config {
		sb.WriteString(fmt.Sprintf("    %s = \"%s\"\n", key, value))
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	return sb.String()
}

func (e *Executor) acquireLock(rc *eos_io.RuntimeContext, component, environment string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	lockKey := fmt.Sprintf("terraform/%s/%s/lock", environment, component)

	// Create session
	session, _, err := e.consulClient.Session().Create(&api.SessionEntry{
		Name:     fmt.Sprintf("terraform-%s-%s", component, environment),
		TTL:      "600s",
		Behavior: "delete",
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	// Try to acquire lock
	acquired, _, err := e.consulClient.KV().Acquire(&api.KVPair{
		Key:     lockKey,
		Value:   []byte(session),
		Session: session,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		return "", fmt.Errorf("lock is held by another process")
	}

	logger.Debug("Acquired Terraform lock",
		zap.String("component", component),
		zap.String("environment", environment),
		zap.String("session", session))

	return session, nil
}

func (e *Executor) releaseLock(rc *eos_io.RuntimeContext, session string) {
	if session == "" {
		return
	}

	logger := otelzap.Ctx(rc.Ctx)
	_, err := e.consulClient.Session().Destroy(session, nil)
	if err != nil {
		logger.Warn("Failed to release lock", zap.Error(err))
	}
}

func (e *Executor) getProviderCredentials(rc *eos_io.RuntimeContext, component string) (map[string]string, error) {
	// Map components to required providers
	providerMap := map[string][]string{
		"boundary": {"aws", "tls"},
		"consul":   {"aws", "consul"},
		"vault":    {"aws", "vault"},
		"hecate":   {"aws", "cloudflare"},
		"hera":     {"azure", "kubernetes"},
	}

	envVars := make(map[string]string)
	providers := providerMap[component]

	for _, provider := range providers {
		creds, err := e.vaultClient.GetSecret(rc.Ctx, fmt.Sprintf("providers/%s", provider))
		if err != nil {
			return nil, fmt.Errorf("failed to get %s credentials: %w", provider, err)
		}

		// Map credentials to environment variables
		if creds != nil && creds.Data != nil {
			switch provider {
			case "aws":
				if v, ok := creds.Data["access_key"].(string); ok {
					envVars["AWS_ACCESS_KEY_ID"] = v
				}
				if v, ok := creds.Data["secret_key"].(string); ok {
					envVars["AWS_SECRET_ACCESS_KEY"] = v
				}
				if v, ok := creds.Data["region"].(string); ok {
					envVars["AWS_REGION"] = v
				}
			case "azure":
				if v, ok := creds.Data["client_id"].(string); ok {
					envVars["ARM_CLIENT_ID"] = v
				}
				if v, ok := creds.Data["client_secret"].(string); ok {
					envVars["ARM_CLIENT_SECRET"] = v
				}
				if v, ok := creds.Data["subscription_id"].(string); ok {
					envVars["ARM_SUBSCRIPTION_ID"] = v
				}
				if v, ok := creds.Data["tenant_id"].(string); ok {
					envVars["ARM_TENANT_ID"] = v
				}
			case "hetzner":
				if v, ok := creds.Data["api_token"].(string); ok {
					envVars["HCLOUD_TOKEN"] = v
				}
			case "cloudflare":
				if v, ok := creds.Data["api_token"].(string); ok {
					envVars["CLOUDFLARE_API_TOKEN"] = v
				}
				if v, ok := creds.Data["zone_id"].(string); ok {
					envVars["CLOUDFLARE_ZONE_ID"] = v
				}
			}
		}
	}

	return envVars, nil
}

func (e *Executor) generateTfvars(rc *eos_io.RuntimeContext, component, environment string, additionalVars map[string]any) map[string]any {
	tfvars := make(map[string]any)

	// Add standard variables
	tfvars["environment"] = environment
	tfvars["component"] = component
	tfvars["deployment_id"] = e.generateDeploymentID()
	tfvars["managed_by"] = "eos-infrastructure-compiler"

	// Add additional variables
	for k, v := range additionalVars {
		tfvars[k] = v
	}

	// Resolve inter-component dependencies
	deps := e.resolveComponentDependencies(rc, component, environment)
	for k, v := range deps {
		tfvars[k] = v
	}

	return tfvars
}

func (e *Executor) resolveComponentDependencies(rc *eos_io.RuntimeContext, component, environment string) map[string]any {
	deps := make(map[string]any)
	logger := otelzap.Ctx(rc.Ctx)

	// Define dependency map
	dependencyMap := map[string]map[string]string{
		"boundary": {
			"vault_address":  "vault:cluster_endpoint",
			"consul_address": "consul:cluster_endpoint",
		},
		"hecate": {
			"boundary_address": "boundary:controller_endpoint",
			"consul_address":   "consul:cluster_endpoint",
			"vault_address":    "vault:cluster_endpoint",
		},
		"hera": {
			"vault_address":    "vault:cluster_endpoint",
			"consul_address":   "consul:cluster_endpoint",
			"boundary_address": "boundary:controller_endpoint",
		},
	}

	if componentDeps, ok := dependencyMap[component]; ok {
		for varName, depPath := range componentDeps {
			parts := strings.Split(depPath, ":")
			if len(parts) != 2 {
				continue
			}

			depComponent, outputKey := parts[0], parts[1]
			consulKey := fmt.Sprintf("terraform/%s/%s/outputs/%s", environment, depComponent, outputKey)

			kvPair, _, err := e.consulClient.KV().Get(consulKey, nil)
			if err != nil {
				logger.Warn("Failed to resolve dependency",
					zap.String("component", component),
					zap.String("dependency", depPath),
					zap.Error(err))
				continue
			}

			if kvPair != nil && kvPair.Value != nil {
				var value any
				if err := json.Unmarshal(kvPair.Value, &value); err == nil {
					deps[varName] = value
				}
			}
		}
	}

	return deps
}

func (e *Executor) storeOutputsInConsul(rc *eos_io.RuntimeContext, component, environment string, outputs map[string]Output) error {
	for key, output := range outputs {
		consulKey := fmt.Sprintf("terraform/%s/%s/outputs/%s", environment, component, key)
		value, err := json.Marshal(output.Value)
		if err != nil {
			return fmt.Errorf("failed to marshal output %s: %w", key, err)
		}

		_, err = e.consulClient.KV().Put(&api.KVPair{
			Key:   consulKey,
			Value: value,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to store output %s: %w", key, err)
		}
	}
	return nil
}

func (e *Executor) verifyPreconditions(rc *eos_io.RuntimeContext, component, environment string) error {
	// Define component dependencies
	preconditions := map[string][]string{
		"vault":    {},
		"consul":   {},
		"boundary": {"vault", "consul"},
		"hecate":   {"vault", "consul", "boundary"},
		"hera":     {"vault", "consul", "boundary"},
	}

	deps, ok := preconditions[component]
	if !ok {
		return nil
	}

	for _, dep := range deps {
		if !e.componentIsHealthy(rc, dep, environment) {
			return fmt.Errorf("dependency %s is not healthy", dep)
		}
	}

	return nil
}

func (e *Executor) componentIsHealthy(_ *eos_io.RuntimeContext, component, environment string) bool {
	// Check Consul for component health
	healthKey := fmt.Sprintf("terraform/%s/%s/health", environment, component)
	kvPair, _, err := e.consulClient.KV().Get(healthKey, nil)
	if err != nil || kvPair == nil {
		return false
	}

	return string(kvPair.Value) == "healthy"
}

func (e *Executor) createStateSnapshot(_ *eos_io.RuntimeContext, component, environment string) (string, error) {
	workspace := e.getWorkspace(component, environment)
	stateFile := filepath.Join(workspace.Path, "terraform.tfstate")

	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		// No state file yet
		return "", nil
	}

	snapshotID := e.generateDeploymentID()
	snapshotPath := filepath.Join(workspace.Path, fmt.Sprintf(".snapshots/%s.tfstate", snapshotID))

	// Create snapshot directory
	if err := os.MkdirAll(filepath.Dir(snapshotPath), shared.ServiceDirPerm); err != nil {
		return "", fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	// Copy state file
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return "", fmt.Errorf("failed to read state file: %w", err)
	}

	if err := os.WriteFile(snapshotPath, data, shared.ConfigFilePerm); err != nil {
		return "", fmt.Errorf("failed to write snapshot: %w", err)
	}

	return snapshotID, nil
}

func (e *Executor) rollbackToSnapshot(rc *eos_io.RuntimeContext, component, environment, snapshotID string) *RollbackResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Rolling back to snapshot",
		zap.String("component", component),
		zap.String("environment", environment),
		zap.String("snapshot_id", snapshotID))

	workspace := e.getWorkspace(component, environment)
	snapshotPath := filepath.Join(workspace.Path, fmt.Sprintf(".snapshots/%s.tfstate", snapshotID))
	stateFile := filepath.Join(workspace.Path, "terraform.tfstate")

	// Check if snapshot exists
	if _, err := os.Stat(snapshotPath); os.IsNotExist(err) {
		return &RollbackResult{
			Success: false,
			Error:   "snapshot not found",
		}
	}

	// Copy snapshot back to state file
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		return &RollbackResult{
			Success: false,
			Error:   fmt.Sprintf("failed to read snapshot: %v", err),
		}
	}

	if err := os.WriteFile(stateFile, data, shared.ConfigFilePerm); err != nil {
		return &RollbackResult{
			Success: false,
			Error:   fmt.Sprintf("failed to restore state: %v", err),
		}
	}

	// Run terraform refresh to sync with actual resources
	envVars, _ := e.getProviderCredentials(rc, component)

	// Set environment variables in current process for terraform
	for k, v := range envVars {
		_ = os.Setenv(k, v)
	}

	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"refresh"},
		Dir:     workspace.Path,
		Capture: true,
	})

	if err != nil {
		return &RollbackResult{
			Success: false,
			Error:   fmt.Sprintf("failed to refresh state: %v", err),
		}
	}

	return &RollbackResult{
		Success: true,
	}
}

func (e *Executor) storeWorkspaceMetadata(_ *eos_io.RuntimeContext, workspace *Workspace, status string) error {
	metadata := map[string]any{
		"component":   workspace.Component,
		"environment": workspace.Environment,
		"path":        workspace.Path,
		"status":      status,
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	key := fmt.Sprintf("terraform/%s/%s/metadata", workspace.Environment, workspace.Component)
	_, err = e.consulClient.KV().Put(&api.KVPair{
		Key:   key,
		Value: data,
	}, nil)

	return err
}

func (e *Executor) updateComponentMetadata(rc *eos_io.RuntimeContext, component, environment, status, _ string) error {
	return e.storeWorkspaceMetadata(rc, e.getWorkspace(component, environment), status)
}

func (e *Executor) runPostApplyHooks(rc *eos_io.RuntimeContext, component, environment string, outputs map[string]Output) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running post-apply hooks",
		zap.String("component", component),
		zap.String("environment", environment))

	// Component-specific hooks
	switch component {
	case "vault":
		return e.configureVaultPostDeploy(rc, outputs)
	case "consul":
		return e.configureConsulPostDeploy(rc, outputs)
	case "boundary":
		return e.configureBoundaryPostDeploy(rc, outputs)
	case "hecate":
		return e.configureHecatePostDeploy(rc, outputs)
	case "hera":
		return e.configureHeraPostDeploy(rc, outputs)
	}

	return nil
}

func (e *Executor) configureVaultPostDeploy(_ *eos_io.RuntimeContext, _ map[string]Output) error {
	// Implement Vault post-deployment configuration
	// In production, would configure Vault policies and auth methods
	return nil
}

func (e *Executor) configureConsulPostDeploy(_ *eos_io.RuntimeContext, _ map[string]Output) error {
	// Implement Consul post-deployment configuration
	// In production, would configure Consul ACLs and service mesh
	return nil
}

func (e *Executor) configureBoundaryPostDeploy(_ *eos_io.RuntimeContext, _ map[string]Output) error {
	// Implement Boundary post-deployment configuration
	// In production, would configure Boundary targets and host catalogs
	return nil
}

func (e *Executor) configureHecatePostDeploy(_ *eos_io.RuntimeContext, _ map[string]Output) error {
	// Implement Hecate post-deployment configuration
	// In production, would configure routing and auth policies
	return nil
}

func (e *Executor) configureHeraPostDeploy(_ *eos_io.RuntimeContext, _ map[string]Output) error {
	// Implement Hera post-deployment configuration
	// In production, would configure monitoring and alerting
	return nil
}

func (e *Executor) cleanupConsulEntries(_ *eos_io.RuntimeContext, component, environment string) error {
	prefix := fmt.Sprintf("terraform/%s/%s/", environment, component)
	_, err := e.consulClient.KV().DeleteTree(prefix, nil)
	return err
}

func (e *Executor) generateDeploymentID() string {
	return fmt.Sprintf("%d-%s", time.Now().Unix(), generateRandomString(8))
}

// Helper functions
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
