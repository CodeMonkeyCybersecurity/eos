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
	
	// Security settings
	EnableTPM      bool   `json:"enable_tpm"`      // Enable TPM 2.0 emulation
	SecureBoot     bool   `json:"secure_boot"`     // Enable UEFI Secure Boot
	Firmware       string `json:"firmware"`        // Path to UEFI firmware (e.g., "/usr/share/OVMF/OVMF_CODE.fd")
	NVRAM          string `json:"nvram"`           // Path to NVRAM template (e.g., "/usr/share/OVMF/OVMF_VARS.fd")
	TPMVersion     string `json:"tpm_version"`     // TPM version ("2.0" or "1.2")
	TPMType        string `json:"tpm_type"`        // TPM type ("emulator" or "passthrough")
	TPMBackend    string `json:"tpm_backend"`      // TPM backend ("emulator" or "crosvm")
	TPMDevicePath string `json:"tpm_device_path"`  // Path to TPM device (for passthrough)
	
	// Disk encryption
	EncryptDisk    bool   `json:"encrypt_disk"`    // Enable disk encryption
	EncryptionKey  string `json:"encryption_key"`  // Encryption key (leave empty for auto-generation)
	
	// Secure boot settings
	SecureBootLoader     string `json:"secure_boot_loader"`      // Path to secure boot loader
	SecureBootKeySource  string `json:"secure_boot_key_source"`  // Source for secure boot keys ("auto", "none", "host")
	SecureBootKeyFile    string `json:"secure_boot_key_file"`    // Path to secure boot key file
	SecureBootCertFile   string `json:"secure_boot_cert_file"`   // Path to secure boot certificate file
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
	// Defensive nil check
	if rc == nil || rc.Ctx == nil {
		return nil, fmt.Errorf("invalid runtime context: context is nil")
	}

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
	// Defensive check for nil context
	if ctx == nil {
		km.logger.Warn("CreateVM received nil context, using background context")
		ctx = context.Background()
	}

	km.logger.Info("Creating VM with Terraform",
		zap.String("name", config.Name),
		zap.Uint("memory", config.Memory),
		zap.Uint("vcpus", config.VCPUs))

	// Generate Terraform configuration
	if err := km.generateVMConfig(config); err != nil {
		return nil, fmt.Errorf("failed to generate Terraform config: %w", err)
	}

	// ASSESS - Initialize Terraform
	km.logger.Info("ASSESS: Initializing Terraform for VM creation",
		zap.String("working_dir", km.workingDir))
	if err := km.tf.Init(ctx); err != nil {
		km.logger.Error("Terraform init failed",
			zap.Error(err),
			zap.String("working_dir", km.workingDir))
		// Check if terraform files exist in working directory
		files, _ := os.ReadDir(km.workingDir)
		for _, f := range files {
			if filepath.Ext(f.Name()) == ".tf" {
				km.logger.Debug("Terraform file found",
					zap.String("file", f.Name()))
			}
		}
		return nil, fmt.Errorf("terraform init failed: %w", err)
	}
	km.logger.Info("Terraform initialized successfully")

	// INTERVENE - Plan the changes
	km.logger.Info("INTERVENE: Planning VM infrastructure changes",
		zap.String("vm_name", config.Name))
	planPath := filepath.Join(km.workingDir, fmt.Sprintf("%s.tfplan", config.Name))
	hasChanges, err := km.tf.Plan(ctx, tfexec.Out(planPath))
	if err != nil {
		km.logger.Error("Terraform plan failed",
			zap.Error(err),
			zap.String("plan_path", planPath),
			zap.String("working_dir", km.workingDir))
		return nil, fmt.Errorf("terraform plan failed: %w", err)
	}
	km.logger.Info("Terraform plan completed",
		zap.Bool("has_changes", hasChanges),
		zap.String("plan_file", planPath))

	if hasChanges {
		// INTERVENE - Apply the changes
		km.logger.Info("Applying Terraform configuration",
			zap.String("vm_name", config.Name))
		if err := km.tf.Apply(ctx, tfexec.DirOrPlan(planPath)); err != nil {
			km.logger.Error("Terraform apply failed",
				zap.Error(err),
				zap.String("plan_path", planPath))
			return nil, fmt.Errorf("terraform apply failed: %w", err)
		}
		km.logger.Info("Terraform apply completed successfully",
			zap.String("vm_name", config.Name))
	} else {
		km.logger.Info("No changes required, VM already exists",
			zap.String("vm_name", config.Name))
	}

	// EVALUATE - Get VM information
	km.logger.Info("EVALUATE: Retrieving VM information")
	vmInfo, err := km.getVMInfo(ctx, config.Name)
	if err != nil {
		km.logger.Error("Failed to get VM info after creation",
			zap.Error(err),
			zap.String("vm_name", config.Name))
		return nil, fmt.Errorf("failed to get VM info: %w", err)
	}

	km.logger.Info("VM created and verified successfully",
		zap.String("name", vmInfo.Name),
		zap.String("uuid", vmInfo.UUID),
		zap.String("state", vmInfo.State),
		zap.Uint("memory_mb", config.Memory),
		zap.Uint("vcpus", config.VCPUs),
		zap.Uint64("disk_gb", config.DiskSize/(1024*1024*1024)))

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
	// Set default security settings if not provided
	if config.TPMVersion == "" {
		config.TPMVersion = "2.0"
	}
	if config.TPMType == "" {
		config.TPMType = "emulator"
	}
	if config.TPMBackend == "" {
		config.TPMBackend = "emulator"
	}
	if config.Firmware == "" {
		config.Firmware = "/usr/share/OVMF/OVMF_CODE.fd"
	}
	if config.NVRAM == "" {
		config.NVRAM = "/usr/share/OVMF/OVMF_VARS.fd"
	}

	// Use the HCL builder for proper configuration generation
	builder := NewHCLBuilder(km.logger)

	// Add cloud-init disk
	if err := builder.AddCloudInitDisk(config.Name, config.StoragePool, config.UserData, config.MetaData); err != nil {
		return fmt.Errorf("failed to add cloud-init disk: %w", err)
	}

	// Add main disk
	if err := builder.AddVolume(config.Name, config.StoragePool, int64(config.DiskSize), "qcow2", config.EncryptDisk, config.EncryptionKey); err != nil {
		return fmt.Errorf("failed to add main volume: %w", err)
	}

	// Add additional volumes
	for i, vol := range config.Volumes {
		if err := builder.AddAdditionalVolume(config.Name, i, vol); err != nil {
			return fmt.Errorf("failed to add volume %d: %w", i, err)
		}
	}

	// Add the domain (VM) configuration
	if err := builder.AddDomain(config); err != nil {
		return fmt.Errorf("failed to add domain configuration: %w", err)
	}

	// Write the configuration to file
	configPath := filepath.Join(km.workingDir, fmt.Sprintf("%s.tf", config.Name))
	if err := os.WriteFile(configPath, builder.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write VM configuration: %w", err)
	}

	km.logger.Debug("Generated Terraform configuration",
		zap.String("path", configPath),
		zap.Int("size", len(builder.Bytes())))

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
