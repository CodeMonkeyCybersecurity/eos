package unified

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/udisks2"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/kvm"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UnifiedStorageManager provides a unified interface for storage and virtualization management
type UnifiedStorageManager struct {
	diskMgr *udisks2.DiskManager
	kvmMgr  *kvm.KVMManager
	logger  otelzap.LoggerWithCtx
	rc      *eos_io.RuntimeContext
}

// StorageRequest represents a unified storage request
type StorageRequest struct {
	Type        string                 `json:"type"`         // "disk", "vm", "volume"
	Name        string                 `json:"name"`
	Size        uint64                 `json:"size"`
	Filesystem  string                 `json:"filesystem"`
	Encrypted   bool                   `json:"encrypted"`
	MountPoint  string                 `json:"mount_point"`
	VMConfig    *VMStorageConfig       `json:"vm_config,omitempty"`
	Metadata    map[string]string      `json:"metadata"`
}

// VMStorageConfig represents VM-specific storage configuration
type VMStorageConfig struct {
	Memory      uint                   `json:"memory"`
	VCPUs       uint                   `json:"vcpus"`
	Network     string                 `json:"network"`
	OSVariant   string                 `json:"os_variant"`
	SSHKeys     []string               `json:"ssh_keys"`
	CloudInit   string                 `json:"cloud_init"`
	Volumes     []VolumeSpec           `json:"volumes"`
}

// VolumeSpec represents additional volume specification
type VolumeSpec struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size"`
	Format string `json:"format"`
}

// StorageInfo represents unified storage information
type StorageInfo struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Status      string                 `json:"status"`
	Size        uint64                 `json:"size"`
	Used        uint64                 `json:"used"`
	Available   uint64                 `json:"available"`
	Health      string                 `json:"health"`
	Location    string                 `json:"location"`
	Metadata    map[string]string      `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Details     interface{}            `json:"details,omitempty"`
}

// NewUnifiedStorageManager creates a new unified storage manager
func NewUnifiedStorageManager(rc *eos_io.RuntimeContext) (*UnifiedStorageManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize disk manager
	diskMgr, err := udisks2.NewDiskManager(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize disk manager: %w", err)
	}

	// Initialize KVM manager
	kvmMgr, err := kvm.NewKVMManager(rc, "")
	if err != nil {
		diskMgr.Close()
		return nil, fmt.Errorf("failed to initialize KVM manager: %w", err)
	}

	return &UnifiedStorageManager{
		diskMgr: diskMgr,
		kvmMgr:  kvmMgr,
		logger:  logger,
		rc:      rc,
	}, nil
}

// Close closes all underlying managers
func (u *UnifiedStorageManager) Close() error {
	var errs []error

	if err := u.diskMgr.Close(); err != nil {
		errs = append(errs, fmt.Errorf("disk manager close: %w", err))
	}

	if err := u.kvmMgr.Close(); err != nil {
		errs = append(errs, fmt.Errorf("KVM manager close: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// CreateStorage creates storage based on the request type
func (u *UnifiedStorageManager) CreateStorage(ctx context.Context, req *StorageRequest) (*StorageInfo, error) {
	u.logger.Info("Creating storage", 
		zap.String("type", req.Type),
		zap.String("name", req.Name),
		zap.Uint64("size", req.Size))

	switch req.Type {
	case "disk", "volume":
		return u.createDiskVolume(ctx, req)
	case "vm":
		return u.createVMWithStorage(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", req.Type)
	}
}

// DeleteStorage deletes storage based on type
func (u *UnifiedStorageManager) DeleteStorage(ctx context.Context, storageType, name string, force bool) error {
	u.logger.Info("Deleting storage", 
		zap.String("type", storageType),
		zap.String("name", name),
		zap.Bool("force", force))

	switch storageType {
	case "disk", "volume":
		return u.deleteDiskVolume(ctx, name, force)
	case "vm":
		return u.deleteVM(ctx, name, force)
	default:
		return fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// ListStorage lists all storage resources
func (u *UnifiedStorageManager) ListStorage(ctx context.Context, storageType string) ([]*StorageInfo, error) {
	u.logger.Debug("Listing storage", zap.String("type", storageType))

	var allStorage []*StorageInfo

	if storageType == "" || storageType == "disk" || storageType == "volume" {
		diskStorage, err := u.listDiskStorage(ctx)
		if err != nil {
			u.logger.Warn("Failed to list disk storage", zap.Error(err))
		} else {
			allStorage = append(allStorage, diskStorage...)
		}
	}

	if storageType == "" || storageType == "vm" {
		vmStorage, err := u.listVMStorage(ctx)
		if err != nil {
			u.logger.Warn("Failed to list VM storage", zap.Error(err))
		} else {
			allStorage = append(allStorage, vmStorage...)
		}
	}

	return allStorage, nil
}

// GetStorageInfo retrieves information about specific storage
func (u *UnifiedStorageManager) GetStorageInfo(ctx context.Context, storageType, name string) (*StorageInfo, error) {
	switch storageType {
	case "disk", "volume":
		return u.getDiskStorageInfo(ctx, name)
	case "vm":
		return u.getVMStorageInfo(ctx, name)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// ResizeStorage resizes storage
func (u *UnifiedStorageManager) ResizeStorage(ctx context.Context, storageType, name string, newSize uint64) error {
	u.logger.Info("Resizing storage", 
		zap.String("type", storageType),
		zap.String("name", name),
		zap.Uint64("new_size", newSize))

	switch storageType {
	case "disk", "volume":
		return u.diskMgr.ResizeVolume(ctx, name, newSize)
	case "vm":
		return fmt.Errorf("VM resize not yet implemented")
	default:
		return fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// CheckHealth checks the health of storage resources
func (u *UnifiedStorageManager) CheckHealth(ctx context.Context, storageType, name string) (*StorageInfo, error) {
	switch storageType {
	case "disk", "volume":
		health, err := u.diskMgr.GetDiskHealth(ctx, name)
		if err != nil {
			return nil, err
		}

		return &StorageInfo{
			Type:   "disk",
			Name:   name,
			Health: health.Status,
			Status: "healthy",
			Details: health,
		}, nil
	case "vm":
		vms, err := u.kvmMgr.ListVMs(ctx)
		if err != nil {
			return nil, err
		}

		for _, vm := range vms {
			if vm.Name == name {
				return &StorageInfo{
					Type:    "vm",
					Name:    name,
					Status:  vm.State,
					Health:  "unknown", // VM health would need separate implementation
					Details: vm,
				}, nil
			}
		}

		return nil, fmt.Errorf("VM not found: %s", name)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// Private helper methods

func (u *UnifiedStorageManager) createDiskVolume(ctx context.Context, req *StorageRequest) (*StorageInfo, error) {
	volumeReq := &udisks2.VolumeRequest{
		Device:      req.Name, // Assuming name is device path for disks
		Size:        req.Size,
		Filesystem:  req.Filesystem,
		Label:       fmt.Sprintf("eos-%s", req.Name),
		MountPoint:  req.MountPoint,
		Encrypted:   req.Encrypted,
		Metadata:    req.Metadata,
	}

	volumeInfo, err := u.diskMgr.CreateVolume(ctx, volumeReq)
	if err != nil {
		return nil, err
	}

	return &StorageInfo{
		Type:      "volume",
		Name:      volumeInfo.Device,
		Status:    volumeInfo.Status,
		Size:      volumeInfo.Size,
		Health:    "healthy",
		Location:  volumeInfo.MountPoint,
		Metadata:  volumeInfo.Metadata,
		CreatedAt: volumeInfo.CreatedAt,
		Details:   volumeInfo,
	}, nil
}

func (u *UnifiedStorageManager) createVMWithStorage(ctx context.Context, req *StorageRequest) (*StorageInfo, error) {
	if req.VMConfig == nil {
		return nil, fmt.Errorf("VM configuration required for VM storage type")
	}

	// Convert volume specs to KVM format
	volumes := make([]kvm.VolumeConfig, len(req.VMConfig.Volumes))
	for i, vol := range req.VMConfig.Volumes {
		volumes[i] = kvm.VolumeConfig{
			Name:   vol.Name,
			Size:   vol.Size,
			Format: vol.Format,
			Pool:   "default",
		}
	}

	vmConfig := &kvm.VMConfig{
		Name:         req.Name,
		Memory:       req.VMConfig.Memory,
		VCPUs:        req.VMConfig.VCPUs,
		DiskSize:     req.Size,
		NetworkName:  req.VMConfig.Network,
		OSVariant:    req.VMConfig.OSVariant,
		SSHKeys:      req.VMConfig.SSHKeys,
		UserData:     req.VMConfig.CloudInit,
		Volumes:      volumes,
		Tags:         req.Metadata,
		StoragePool:  "default",
		AutoStart:    false,
	}

	vmInfo, err := u.kvmMgr.CreateVM(ctx, vmConfig)
	if err != nil {
		return nil, err
	}

	return &StorageInfo{
		Type:      "vm",
		Name:      vmInfo.Name,
		Status:    vmInfo.State,
		Size:      vmInfo.Memory,
		Health:    "unknown",
		Location:  "kvm",
		Metadata:  vmInfo.Tags,
		CreatedAt: vmInfo.CreatedAt,
		Details:   vmInfo,
	}, nil
}

func (u *UnifiedStorageManager) deleteDiskVolume(ctx context.Context, device string, wipe bool) error {
	return u.diskMgr.UnmountVolume(ctx, device)
}

func (u *UnifiedStorageManager) deleteVM(ctx context.Context, name string, removeStorage bool) error {
	return u.kvmMgr.DestroyVM(ctx, name)
}

func (u *UnifiedStorageManager) listDiskStorage(ctx context.Context) ([]*StorageInfo, error) {
	disks, err := u.diskMgr.DiscoverDisks(ctx)
	if err != nil {
		return nil, err
	}

	storage := make([]*StorageInfo, len(disks))
	for i, disk := range disks {
		storage[i] = &StorageInfo{
			Type:      "disk",
			Name:      disk.Device,
			Status:    "available",
			Size:      disk.Size,
			Health:    disk.Health.Status,
			Location:  disk.Device,
			Metadata:  disk.Metadata,
			Details:   disk,
		}
	}

	return storage, nil
}

func (u *UnifiedStorageManager) listVMStorage(ctx context.Context) ([]*StorageInfo, error) {
	vms, err := u.kvmMgr.ListVMs(ctx)
	if err != nil {
		return nil, err
	}

	storage := make([]*StorageInfo, len(vms))
	for i, vm := range vms {
		storage[i] = &StorageInfo{
			Type:      "vm",
			Name:      vm.Name,
			Status:    vm.State,
			Size:      vm.Memory,
			Health:    "unknown",
			Location:  "kvm",
			Metadata:  vm.Tags,
			CreatedAt: vm.CreatedAt,
			Details:   vm,
		}
	}

	return storage, nil
}

func (u *UnifiedStorageManager) getDiskStorageInfo(ctx context.Context, device string) (*StorageInfo, error) {
	disks, err := u.diskMgr.DiscoverDisks(ctx)
	if err != nil {
		return nil, err
	}

	for _, disk := range disks {
		if disk.Device == device {
			return &StorageInfo{
				Type:      "disk",
				Name:      disk.Device,
				Status:    "available",
				Size:      disk.Size,
				Health:    disk.Health.Status,
				Location:  disk.Device,
				Metadata:  disk.Metadata,
				Details:   disk,
			}, nil
		}
	}

	return nil, fmt.Errorf("disk not found: %s", device)
}

func (u *UnifiedStorageManager) getVMStorageInfo(ctx context.Context, name string) (*StorageInfo, error) {
	vms, err := u.kvmMgr.ListVMs(ctx)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return &StorageInfo{
				Type:      "vm",
				Name:      vm.Name,
				Status:    vm.State,
				Size:      vm.Memory,
				Health:    "unknown",
				Location:  "kvm",
				Metadata:  vm.Tags,
				CreatedAt: vm.CreatedAt,
				Details:   vm,
			}, nil
		}
	}

	return nil, fmt.Errorf("VM not found: %s", name)
}
