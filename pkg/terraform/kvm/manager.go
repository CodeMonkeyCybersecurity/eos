package kvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// KVMManager manages KVM virtual machines using Terraform
type KVMManager struct {
	tf         *tfexec.Terraform
	workingDir string
	logger     otelzap.LoggerWithCtx
	rc         *eos_io.RuntimeContext
}

// VMConfig represents VM configuration
type VMConfig struct {
	Name         string            `json:"name"`
	Memory       uint              `json:"memory"`       // MB
	VCPUs        uint              `json:"vcpus"`
	DiskSize     uint64            `json:"disk_size"`    // bytes
	NetworkName  string            `json:"network_name"`
	OSVariant    string            `json:"os_variant"`
	ImagePath    string            `json:"image_path"`
	SSHKeys      []string          `json:"ssh_keys"`
	UserData     string            `json:"user_data"`
	MetaData     string            `json:"meta_data"`
	Volumes      []VolumeConfig    `json:"volumes"`
	Tags         map[string]string `json:"tags"`
	StoragePool  string            `json:"storage_pool"`
	AutoStart    bool              `json:"auto_start"`
}

// VolumeConfig represents additional volume configuration
type VolumeConfig struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size"`   // bytes
	Format string `json:"format"` // qcow2, raw
	Pool   string `json:"pool"`
}

// VMInfo represents VM information
type VMInfo struct {
	Name       string          `json:"name"`
	UUID       string          `json:"uuid"`
	State      string          `json:"state"`
	Memory     uint64          `json:"memory"`
	VCPUs      uint            `json:"vcpus"`
	Autostart  bool            `json:"autostart"`
	Persistent bool            `json:"persistent"`
	Networks   []NetworkInfo   `json:"networks"`
	Disks      []DiskInfo      `json:"disks"`
	CreatedAt  time.Time       `json:"created_at"`
	Tags       map[string]string `json:"tags"`
}

// NetworkInfo represents network interface information
type NetworkInfo struct {
	Interface string `json:"interface"`
	Network   string `json:"network"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
}

// DiskInfo represents disk information
type DiskInfo struct {
	Target string `json:"target"`
	Size   uint64 `json:"size"`
	Format string `json:"format"`
	Pool   string `json:"pool"`
}

// StoragePool represents storage pool information
type StoragePool struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Path      string `json:"path"`
	Capacity  uint64 `json:"capacity"`
	Available uint64 `json:"available"`
	Active    bool   `json:"active"`
}

// NewKVMManager creates a new KVM manager using Terraform
func NewKVMManager(rc *eos_io.RuntimeContext, workingDir string) (*KVMManager, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	if workingDir == "" {
		workingDir = "/tmp/eos-terraform-kvm"
	}

	// Ensure working directory exists
	if err := os.MkdirAll(workingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize Terraform
	tf, err := tfexec.NewTerraform(workingDir, "terraform")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Terraform: %w", err)
	}

	manager := &KVMManager{
		tf:         tf,
		workingDir: workingDir,
		logger:     logger,
		rc:         rc,
	}

	// Initialize Terraform configuration
	if err := manager.initializeTerraform(rc.Ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize Terraform configuration: %w", err)
	}

	logger.Info("KVM manager initialized", zap.String("working_dir", workingDir))
	return manager, nil
}

// CreateVM creates a new KVM virtual machine
func (km *KVMManager) CreateVM(ctx context.Context, config *VMConfig) (*VMInfo, error) {
	km.logger.Info("Creating VM with Terraform", 
		zap.String("name", config.Name),
		zap.Uint("memory", config.Memory),
		zap.Uint("vcpus", config.VCPUs))

	// Generate Terraform configuration
	if err := km.generateVMConfig(config); err != nil {
		return nil, fmt.Errorf("failed to generate Terraform config: %w", err)
	}

	// Plan and apply
	if err := km.tf.Init(ctx); err != nil {
		return nil, fmt.Errorf("terraform init failed: %w", err)
	}

	planPath := filepath.Join(km.workingDir, fmt.Sprintf("%s.tfplan", config.Name))
	hasChanges, err := km.tf.Plan(ctx, tfexec.Out(planPath))
	if err != nil {
		return nil, fmt.Errorf("terraform plan failed: %w", err)
	}

	if hasChanges {
		if err := km.tf.Apply(ctx, tfexec.DirOrPlan(planPath)); err != nil {
			return nil, fmt.Errorf("terraform apply failed: %w", err)
		}
	}

	// Get VM information
	vmInfo, err := km.getVMInfo(ctx, config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM info: %w", err)
	}

	km.logger.Info("VM created successfully", 
		zap.String("name", vmInfo.Name),
		zap.String("uuid", vmInfo.UUID))

	return vmInfo, nil
}

// DestroyVM destroys a virtual machine
func (km *KVMManager) DestroyVM(ctx context.Context, name string) error {
	km.logger.Info("Destroying VM", zap.String("name", name))

	// Remove VM from Terraform state and destroy
	if err := km.tf.Destroy(ctx); err != nil {
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	km.logger.Info("VM destroyed successfully", zap.String("name", name))
	return nil
}

// ListVMs lists all managed VMs
func (km *KVMManager) ListVMs(ctx context.Context) ([]*VMInfo, error) {
	// Get Terraform state
	state, err := km.tf.Show(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform state: %w", err)
	}

	var vms []*VMInfo
	if state != nil && state.Values != nil && state.Values.RootModule != nil {
		for _, resource := range state.Values.RootModule.Resources {
			if resource.Type == "libvirt_domain" {
				vmInfo, err := km.parseVMFromState(resource)
				if err != nil {
					km.logger.Warn("Failed to parse VM from state", 
						zap.String("name", resource.Name), 
						zap.Error(err))
					continue
				}
				vms = append(vms, vmInfo)
			}
		}
	}

	return vms, nil
}

// CreateStoragePool creates a new storage pool
func (km *KVMManager) CreateStoragePool(ctx context.Context, name, poolType, path string) error {
	km.logger.Info("Creating storage pool", 
		zap.String("name", name),
		zap.String("type", poolType),
		zap.String("path", path))

	// Generate storage pool configuration
	poolConfig := fmt.Sprintf(`
resource "libvirt_pool" "%s" {
  name = "%s"
  type = "%s"
  path = "%s"
}
`, name, name, poolType, path)

	configPath := filepath.Join(km.workingDir, fmt.Sprintf("pool_%s.tf", name))
	if err := os.WriteFile(configPath, []byte(poolConfig), 0644); err != nil {
		return fmt.Errorf("failed to write pool configuration: %w", err)
	}

	// Apply configuration
	if err := km.tf.Init(ctx); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	if err := km.tf.Apply(ctx); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	km.logger.Info("Storage pool created successfully", zap.String("name", name))
	return nil
}

// ListStoragePools lists all storage pools
func (km *KVMManager) ListStoragePools(ctx context.Context) ([]*StoragePool, error) {
	state, err := km.tf.Show(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform state: %w", err)
	}

	var pools []*StoragePool
	if state != nil && state.Values != nil && state.Values.RootModule != nil {
		for _, resource := range state.Values.RootModule.Resources {
			if resource.Type == "libvirt_pool" {
				pool, err := km.parsePoolFromState(resource)
				if err != nil {
					km.logger.Warn("Failed to parse pool from state", 
						zap.String("name", resource.Name), 
						zap.Error(err))
					continue
				}
				pools = append(pools, pool)
			}
		}
	}

	return pools, nil
}

// Close cleans up resources
func (km *KVMManager) Close() error {
	// Cleanup temporary files if needed
	return nil
}

// Helper methods

func (km *KVMManager) initializeTerraform(ctx context.Context) error {
	// Create main.tf with provider configuration
	mainConfig := `
terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}
`

	mainPath := filepath.Join(km.workingDir, "main.tf")
	if err := os.WriteFile(mainPath, []byte(mainConfig), 0644); err != nil {
		return fmt.Errorf("failed to write main.tf: %w", err)
	}

	return nil
}

func (km *KVMManager) generateVMConfig(config *VMConfig) error {
	// Generate cloud-init ISO configuration
	cloudInitConfig := fmt.Sprintf(`
resource "libvirt_cloudinit_disk" "%s_cloudinit" {
  name      = "%s-cloudinit.iso"
  pool      = "%s"
  user_data = <<-EOF
%s
EOF
  meta_data = <<-EOF
%s
EOF
}
`, config.Name, config.Name, config.StoragePool, config.UserData, config.MetaData)

	// Generate main disk configuration
	diskConfig := fmt.Sprintf(`
resource "libvirt_volume" "%s_disk" {
  name   = "%s-disk.qcow2"
  pool   = "%s"
  size   = %d
  format = "qcow2"
}
`, config.Name, config.Name, config.StoragePool, config.DiskSize)

	// Generate additional volumes
	var volumeConfigs string
	var volumeAttachments string
	for i, vol := range config.Volumes {
		volumeConfigs += fmt.Sprintf(`
resource "libvirt_volume" "%s_volume_%d" {
  name   = "%s-%s.%s"
  pool   = "%s"
  size   = %d
  format = "%s"
}
`, config.Name, i, config.Name, vol.Name, vol.Format, vol.Pool, vol.Size, vol.Format)

		volumeAttachments += fmt.Sprintf(`
  disk {
    volume_id = libvirt_volume.%s_volume_%d.id
  }
`, config.Name, i)
	}

	// Generate VM configuration
	vmConfig := fmt.Sprintf(`
resource "libvirt_domain" "%s" {
  name   = "%s"
  memory = %d
  vcpu   = %d
  
  cloudinit = libvirt_cloudinit_disk.%s_cloudinit.id
  
  network_interface {
    network_name = "%s"
  }
  
  disk {
    volume_id = libvirt_volume.%s_disk.id
  }
  %s
  
  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }
  
  console {
    type        = "pty"
    target_type = "virtio"
    target_port = "1"
  }
  
  graphics {
    type        = "spice"
    listen_type = "address"
    autoport    = true
  }
  
  autostart = %t
}
`, config.Name, config.Name, config.Memory, config.VCPUs, config.Name, 
   config.NetworkName, config.Name, volumeAttachments, config.AutoStart)

	// Write complete configuration
	fullConfig := cloudInitConfig + diskConfig + volumeConfigs + vmConfig
	configPath := filepath.Join(km.workingDir, fmt.Sprintf("%s.tf", config.Name))
	
	if err := os.WriteFile(configPath, []byte(fullConfig), 0644); err != nil {
		return fmt.Errorf("failed to write VM configuration: %w", err)
	}

	return nil
}

func (km *KVMManager) getVMInfo(ctx context.Context, name string) (*VMInfo, error) {
	state, err := km.tf.Show(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform state: %w", err)
	}

	if state == nil || state.Values == nil || state.Values.RootModule == nil {
		return nil, fmt.Errorf("no Terraform state found")
	}

	for _, resource := range state.Values.RootModule.Resources {
		if resource.Type == "libvirt_domain" && resource.Name == name {
			return km.parseVMFromState(resource)
		}
	}

	return nil, fmt.Errorf("VM %s not found in state", name)
}

func (km *KVMManager) parseVMFromState(resource interface{}) (*VMInfo, error) {
	// This is a simplified parser - in practice you'd need to handle
	// the complex Terraform state structure properly
	resourceBytes, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resource: %w", err)
	}

	var resourceData map[string]interface{}
	if err := json.Unmarshal(resourceBytes, &resourceData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource: %w", err)
	}

	// Extract VM information from resource data
	vmInfo := &VMInfo{
		Name:      getString(resourceData, "name"),
		UUID:      getString(resourceData, "uuid"),
		State:     "running", // Default state
		CreatedAt: time.Now(),
		Tags:      make(map[string]string),
	}

	if values, ok := resourceData["values"].(map[string]interface{}); ok {
		if memory, ok := values["memory"].(float64); ok {
			vmInfo.Memory = uint64(memory)
		}
		if vcpu, ok := values["vcpu"].(float64); ok {
			vmInfo.VCPUs = uint(vcpu)
		}
		if autostart, ok := values["autostart"].(bool); ok {
			vmInfo.Autostart = autostart
		}
	}

	return vmInfo, nil
}

func (km *KVMManager) parsePoolFromState(resource interface{}) (*StoragePool, error) {
	// Similar to parseVMFromState but for storage pools
	resourceBytes, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resource: %w", err)
	}

	var resourceData map[string]interface{}
	if err := json.Unmarshal(resourceBytes, &resourceData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource: %w", err)
	}

	pool := &StoragePool{
		Name:   getString(resourceData, "name"),
		Type:   getString(resourceData, "type"),
		Path:   getString(resourceData, "path"),
		Active: true, // Default
	}

	return pool, nil
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}
