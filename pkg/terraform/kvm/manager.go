package kvm

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// KVMManager manages KVM virtual machines using Terraform
type KVMManager struct {
	workingDir string
	logger     otelzap.LoggerWithCtx
	rc         *eos_io.RuntimeContext
	execMgr    *ExecManager // Direct terraform-exec manager
}

// VMConfig represents VM configuration
type VMConfig struct {
	Name        string            `json:"name"`
	Memory      uint              `json:"memory"` // MB
	VCPUs       uint              `json:"vcpus"`
	DiskSize    uint64            `json:"disk_size"` // bytes
	NetworkName string            `json:"network_name"`
	OSVariant   string            `json:"os_variant"`
	ImagePath   string            `json:"image_path"`
	SSHKeys     []string          `json:"ssh_keys"`
	UserData    string            `json:"user_data"`
	MetaData    string            `json:"meta_data"`
	Volumes     []VolumeConfig    `json:"volumes"`
	Tags        map[string]string `json:"tags"`
	StoragePool string            `json:"storage_pool"`
	AutoStart   bool              `json:"auto_start"`

	// Security settings
	EnableTPM      bool   `json:"enable_tpm"`      // Enable TPM 2.0 emulation
	SecureBoot     bool   `json:"secure_boot"`     // Enable UEFI Secure Boot
	Firmware       string `json:"firmware"`        // Path to UEFI firmware (e.g., "/usr/share/OVMF/OVMF_CODE.fd")
	NVRAM          string `json:"nvram"`           // Path to NVRAM template (e.g., "/usr/share/OVMF/OVMF_VARS.fd")
	EncryptDisk    bool   `json:"encrypt_disk"`    // Enable disk encryption
	EncryptionKey  string `json:"encryption_key"`  // Encryption key for disk
	TPMVersion     string `json:"tpm_version"`     // TPM version (e.g., "2.0")
	TPMBackend     string `json:"tpm_backend"`     // TPM backend type
	RestrictAccess bool   `json:"restrict_access"` // Restrict VM access to local network only
	Isolation      bool   `json:"isolation"`       // Enable VM isolation
}

// VMInfo represents VM information
type VMInfo struct {
	UUID        string            `json:"uuid"`
	Name        string            `json:"name"`
	State       string            `json:"state"`
	Memory      uint64            `json:"memory"`
	VCPUs       uint              `json:"vcpus"`
	IPAddress   string            `json:"ip_address"`
	MACAddress  string            `json:"mac_address"`
	DiskSize    uint64            `json:"disk_size"`
	StoragePool string            `json:"storage_pool"`
	CreatedAt   time.Time         `json:"created_at"`
	Tags        map[string]string `json:"tags"`
}

// VolumeConfig represents additional volume configuration
type VolumeConfig struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size"`   // bytes
	Format string `json:"format"` // qcow2, raw, etc.
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
	if err := os.MkdirAll(workingDir, shared.ServiceDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize ExecManager for direct terraform-exec control
	execMgr, err := NewExecManager(rc.Ctx, workingDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ExecManager: %w", err)
	}

	manager := &KVMManager{
		workingDir: workingDir,
		logger:     logger,
		rc:         rc,
		execMgr:    execMgr,
	}

	logger.Info("KVM manager initialized with terraform-exec",
		zap.String("working_dir", workingDir))
	return manager, nil
}

// CreateVM creates a new KVM virtual machine
func (km *KVMManager) CreateVM(ctx context.Context, config *VMConfig) (*VMInfo, error) {
	km.logger.Info("Creating VM using terraform-exec")
	if err := km.execMgr.CreateVMDirect(config); err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	// Get VM state from terraform
	vmState, err := km.execMgr.GetVMState(config.Name)
	if err != nil {
		km.logger.Warn("Failed to get VM state after creation", zap.Error(err))
	}

	// Extract VM info from state
	vmInfo := &VMInfo{
		Name:      config.Name,
		State:     "running",
		CreatedAt: time.Now(),
		Tags:      config.Tags,
	}

	if vmState != nil {
		if values, ok := vmState["values"].(map[string]interface{}); ok {
			if id, ok := values["id"].(string); ok {
				vmInfo.UUID = id
			}
			if memory, ok := values["memory"].(float64); ok {
				vmInfo.Memory = uint64(memory)
			}
			if vcpu, ok := values["vcpu"].(float64); ok {
				vmInfo.VCPUs = uint(vcpu)
			}
		}
	}

	return vmInfo, nil
}

// DestroyVM destroys a virtual machine
func (km *KVMManager) DestroyVM(ctx context.Context, name string) error {
	return km.execMgr.DestroyVM(name)
}

// ListVMs lists all managed VMs
func (km *KVMManager) ListVMs(ctx context.Context) ([]*VMInfo, error) {
	return km.execMgr.ListVMs()
}

// Close cleans up resources
func (km *KVMManager) Close() error {
	// Nothing to clean up with ExecManager
	return nil
}
