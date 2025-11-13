// pkg/terraform/kvm/exec_manager.go

package kvm

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExecManager provides direct Terraform control using terraform-exec
// This is Phase 3 of the migration plan - using terraform-exec API directly
type ExecManager struct {
	tf         *tfexec.Terraform
	workingDir string
	logger     otelzap.LoggerWithCtx
	ctx        context.Context
	// lockMgr removed - keeping it simple
}

// NewExecManager creates a new terraform-exec based manager - SIMPLIFIED
func NewExecManager(ctx context.Context, workingDir string, logger otelzap.LoggerWithCtx) (*ExecManager, error) {
	// Ensure working directory exists
	if err := os.MkdirAll(workingDir, shared.ServiceDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Find terraform binary - use terraform in PATH
	execPath := "terraform"

	// Create terraform executor
	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create terraform executor: %w", err)
	}

	return &ExecManager{
		tf:         tf,
		workingDir: workingDir,
		logger:     logger,
		ctx:        ctx,
	}, nil
}

// CreateVMDirect creates a VM using direct terraform-exec API - SIMPLIFIED VERSION
func (em *ExecManager) CreateVMDirect(config *VMConfig) error {
	em.logger.Info("Creating VM using terraform-exec",
		zap.String("vm_name", config.Name),
		zap.String("working_dir", em.workingDir))

	// Step 1: Generate configuration in memory (simple JSON)
	tfConfig, err := em.generateInMemoryConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Step 2: Write configuration file
	configPath := filepath.Join(em.workingDir, "main.tf.json")
	if err := os.WriteFile(configPath, tfConfig, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Step 3: Initialize Terraform
	em.logger.Info("Running terraform init")
	if err := em.tf.Init(em.ctx, tfexec.Upgrade(true)); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Step 4: Plan the changes
	em.logger.Info("Running terraform plan")
	hasChanges, err := em.tf.Plan(em.ctx)
	if err != nil {
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	if !hasChanges {
		em.logger.Info("No changes required, VM may already exist")
		return nil
	}

	// Step 5: Apply the changes
	em.logger.Info("Running terraform apply")
	if err := em.tf.Apply(em.ctx); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	// Step 6: Get outputs
	em.logger.Info("VM creation completed, retrieving outputs")
	outputs, err := em.tf.Output(em.ctx)
	if err != nil {
		em.logger.Warn("Failed to get terraform outputs", zap.Error(err))
	} else {
		for name, output := range outputs {
			em.logger.Info("Terraform output",
				zap.String("name", name),
				zap.Any("value", output.Value))
		}
	}

	em.logger.Info("EVALUATE: VM created successfully using terraform-exec",
		zap.String("vm_name", config.Name))

	return nil
}

// generateInMemoryConfig generates SIMPLE Terraform JSON configuration
func (em *ExecManager) generateInMemoryConfig(config *VMConfig) ([]byte, error) {
	// Default cloud-init if not provided
	if config.UserData == "" {
		config.UserData = `#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: $6$rounds=4096$saltsalt$7xmvWaIOaKB5QZEV.IXnP4YW9BJHZkDSdTLqk8xrNDrPP2LR0JcR9Qx7XQqGBFqJmYqVqLqaWgtmNDYiJQfz71`
	}

	if config.MetaData == "" {
		config.MetaData = fmt.Sprintf("instance-id: %s\nlocal-hostname: %s", config.Name, config.Name)
	}

	// Create simple Terraform JSON configuration
	tfConfig := map[string]interface{}{
		"terraform": map[string]interface{}{
			"required_providers": map[string]interface{}{
				"libvirt": map[string]interface{}{
					"source": "dmacvicar/libvirt",
				},
			},
		},
		"provider": map[string]interface{}{
			"libvirt": map[string]interface{}{
				"uri": "qemu:///system",
			},
		},
		"resource": map[string]interface{}{
			"libvirt_volume": map[string]interface{}{
				"ubuntu_base": map[string]interface{}{
					"name":   config.Name + "-base.qcow2",
					"source": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
					"pool":   config.StoragePool,
					"format": "qcow2",
				},
				"vm_disk": map[string]interface{}{
					"name":           config.Name + ".qcow2",
					"base_volume_id": "${libvirt_volume.ubuntu_base.id}",
					"pool":           config.StoragePool,
					"size":           config.DiskSize,
				},
			},
			"libvirt_cloudinit_disk": map[string]interface{}{
				"cloudinit": map[string]interface{}{
					"name":      config.Name + "-cloudinit.iso",
					"user_data": config.UserData,
					"meta_data": config.MetaData,
					"pool":      config.StoragePool,
				},
			},
			"libvirt_domain": map[string]interface{}{
				"vm": map[string]interface{}{
					"name":      config.Name,
					"memory":    config.Memory,
					"vcpu":      config.VCPUs,
					"cloudinit": "${libvirt_cloudinit_disk.cloudinit.id}",
					"network_interface": []interface{}{
						map[string]interface{}{
							"network_name":   config.NetworkName,
							"wait_for_lease": true,
						},
					},
					"disk": []interface{}{
						map[string]interface{}{
							"volume_id": "${libvirt_volume.vm_disk.id}",
						},
					},
					"console": []interface{}{
						map[string]interface{}{
							"type":        "pty",
							"target_type": "serial",
							"target_port": "0",
						},
					},
					"graphics": []interface{}{
						map[string]interface{}{
							"type":        "spice",
							"listen_type": "none",
							"autoport":    true,
						},
					},
				},
			},
		},
		"output": map[string]interface{}{
			"vm_ip": map[string]interface{}{
				"value": "${libvirt_domain.vm.network_interface[0].addresses[0]}",
			},
		},
	}

	return json.MarshalIndent(tfConfig, "", "  ")
}

// DestroyVM destroys a VM using terraform-exec
func (em *ExecManager) DestroyVM(vmName string) error {
	em.logger.Info("ASSESS: Destroying VM using terraform-exec",
		zap.String("vm_name", vmName))

	// Run targeted destroy
	destroyOpts := []tfexec.DestroyOption{
		tfexec.Target(fmt.Sprintf("libvirt_domain.%s", vmName)),
	}

	em.logger.Info("INTERVENE: Running terraform destroy")
	if err := em.tf.Destroy(em.ctx, destroyOpts...); err != nil {
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	em.logger.Info("EVALUATE: VM destroyed successfully",
		zap.String("vm_name", vmName))

	return nil
}

// GetVMState retrieves the current state of a VM
func (em *ExecManager) GetVMState(vmName string) (map[string]interface{}, error) {
	em.logger.Debug("Getting VM state from Terraform",
		zap.String("vm_name", vmName))

	// Get the state
	state, err := em.tf.Show(em.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform state: %w", err)
	}

	// Find the VM in the state
	if state.Values != nil && state.Values.RootModule != nil {
		for _, resource := range state.Values.RootModule.Resources {
			if resource.Type == "libvirt_domain" && resource.Name == vmName {
				// Convert to map for easier access
				resourceBytes, err := json.Marshal(resource)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal resource: %w", err)
				}

				var resourceMap map[string]interface{}
				if err := json.Unmarshal(resourceBytes, &resourceMap); err != nil {
					return nil, fmt.Errorf("failed to unmarshal resource: %w", err)
				}

				return resourceMap, nil
			}
		}
	}

	return nil, fmt.Errorf("VM %s not found in state", vmName)
}

// RefreshState refreshes the Terraform state
func (em *ExecManager) RefreshState() error {
	em.logger.Debug("Refreshing Terraform state")

	return em.tf.Refresh(em.ctx)
}

// ImportVM imports an existing VM into Terraform state
func (em *ExecManager) ImportVM(vmName, vmID string) error {
	em.logger.Info("ASSESS: Importing existing VM into Terraform state",
		zap.String("vm_name", vmName),
		zap.String("vm_id", vmID))

	// Import the resource
	resourceAddress := fmt.Sprintf("libvirt_domain.%s", vmName)

	em.logger.Info("INTERVENE: Running terraform import")
	if err := em.tf.Import(em.ctx, resourceAddress, vmID); err != nil {
		return fmt.Errorf("terraform import failed: %w", err)
	}

	em.logger.Info("EVALUATE: VM imported successfully",
		zap.String("vm_name", vmName))

	return nil
}

// PlanChanges shows what changes would be made without applying them
func (em *ExecManager) PlanChanges() (bool, error) {
	em.logger.Debug("Planning Terraform changes")

	hasChanges, err := em.tf.Plan(em.ctx)
	if err != nil {
		return false, fmt.Errorf("terraform plan failed: %w", err)
	}

	return hasChanges, nil
}

// GetWorkspaces lists available Terraform workspaces
func (em *ExecManager) GetWorkspaces() ([]string, error) {
	workspaces, current, err := em.tf.WorkspaceList(em.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}

	// Mark current workspace
	for i, ws := range workspaces {
		if ws == current {
			workspaces[i] = fmt.Sprintf("%s (current)", ws)
		}
	}

	return workspaces, nil
}

// SelectWorkspace switches to a different Terraform workspace
func (em *ExecManager) SelectWorkspace(name string) error {
	em.logger.Info("Switching Terraform workspace",
		zap.String("workspace", name))

	return em.tf.WorkspaceSelect(em.ctx, name)
}

// CreateWorkspace creates a new Terraform workspace
func (em *ExecManager) CreateWorkspace(name string) error {
	em.logger.Info("Creating Terraform workspace",
		zap.String("workspace", name))

	return em.tf.WorkspaceNew(em.ctx, name)
}


// ListVMs lists all VMs managed by Terraform
func (em *ExecManager) ListVMs() ([]*VMInfo, error) {
	em.logger.Debug("Listing all VMs from Terraform state")

	// Get the state
	state, err := em.tf.Show(em.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform state: %w", err)
	}

	var vms []*VMInfo

	if state.Values != nil && state.Values.RootModule != nil {
		for _, resource := range state.Values.RootModule.Resources {
			if resource.Type == "libvirt_domain" {
				// Convert resource to VMInfo
				resourceBytes, err := json.Marshal(resource)
				if err != nil {
					em.logger.Warn("Failed to marshal resource", zap.Error(err))
					continue
				}

				var resourceMap map[string]interface{}
				if err := json.Unmarshal(resourceBytes, &resourceMap); err != nil {
					em.logger.Warn("Failed to unmarshal resource", zap.Error(err))
					continue
				}

				vmInfo := &VMInfo{
					Name:  getString(resourceMap, "name"),
					State: "running", // Default state
					Tags:  make(map[string]string),
				}

				// Extract values
				if values, ok := resourceMap["values"].(map[string]interface{}); ok {
					if id, ok := values["id"].(string); ok {
						vmInfo.UUID = id
					}
					if memory, ok := values["memory"].(float64); ok {
						vmInfo.Memory = uint64(memory)
					}
					if vcpu, ok := values["vcpu"].(float64); ok {
						vmInfo.VCPUs = uint(vcpu)
					}
					if name, ok := values["name"].(string); ok {
						vmInfo.Name = name
					}
				}

				vms = append(vms, vmInfo)
			}
		}
	}

	em.logger.Info("Found VMs in Terraform state", zap.Int("count", len(vms)))
	return vms, nil
}

// UpdateVM updates a VM's configuration
func (em *ExecManager) UpdateVM(config *VMConfig) error {
	em.logger.Info("ASSESS: Updating VM configuration",
		zap.String("vm_name", config.Name))

	// Generate new configuration
	tfConfig, err := em.generateInMemoryConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Write configuration
	configPath := filepath.Join(em.workingDir, "main.tf.json")
	if err := os.WriteFile(configPath, tfConfig, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Plan the changes
	em.logger.Info("INTERVENE: Planning VM update")
	hasChanges, err := em.tf.Plan(em.ctx)
	if err != nil {
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	if !hasChanges {
		em.logger.Info("No changes required for VM update")
		return nil
	}

	// Apply the changes
	em.logger.Info("INTERVENE: Applying VM updates")
	if err := em.tf.Apply(em.ctx); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	em.logger.Info("EVALUATE: VM updated successfully",
		zap.String("vm_name", config.Name))

	return nil
}

// getString is a helper to extract string values from interface maps
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}