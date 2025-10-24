package udisks2

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/godbus/dbus/v5"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiskManager provides safe disk operations using D-Bus/udisks2
type DiskManager struct {
	conn   *dbus.Conn
	logger otelzap.LoggerWithCtx
	rc     *eos_io.RuntimeContext
}

// Type aliases for storage types - use unified types from storage package
type DiskInfo = storage.DiskInfo
type PartitionInfo = storage.PartitionInfo
type DiskHealth = storage.DiskHealth

// VolumeRequest represents a volume creation request
type VolumeRequest struct {
	Device     string            `json:"device"`
	Size       uint64            `json:"size"`       // 0 means use entire device
	Filesystem string            `json:"filesystem"` // ext4, xfs, btrfs
	Label      string            `json:"label"`
	MountPoint string            `json:"mount_point"`
	Encrypted  bool              `json:"encrypted"`
	Passphrase string            `json:"passphrase,omitempty"`
	Options    []string          `json:"options"` // mount options
	Metadata   map[string]string `json:"metadata"`
}

// VolumeInfo represents created volume information
type VolumeInfo struct {
	Device     string            `json:"device"`
	UUID       string            `json:"uuid"`
	Size       uint64            `json:"size"`
	Filesystem string            `json:"filesystem"`
	Label      string            `json:"label"`
	MountPoint string            `json:"mount_point"`
	Encrypted  bool              `json:"encrypted"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	Metadata   map[string]string `json:"metadata"`
}

// NewDiskManager creates a new disk manager using D-Bus/udisks2
func NewDiskManager(rc *eos_io.RuntimeContext) (*DiskManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to system D-Bus
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system D-Bus: %w", err)
	}

	// Test udisks2 availability
	obj := conn.Object("org.freedesktop.UDisks2", "/org/freedesktop/UDisks2/Manager")
	var version string
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Manager", "Version").Store(&version)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("udisks2 not available: %w", err)
	}

	logger.Info("Connected to udisks2", zap.String("version", version))

	return &DiskManager{
		conn:   conn,
		logger: logger,
		rc:     rc,
	}, nil
}

// Close closes the D-Bus connection
func (dm *DiskManager) Close() error {
	if dm.conn != nil {
		return dm.conn.Close()
	}
	return nil
}

// DiscoverDisks discovers all available disks
func (dm *DiskManager) DiscoverDisks(ctx context.Context) ([]*DiskInfo, error) {
	dm.logger.Info("Discovering disks via udisks2")

	// Get all block devices
	obj := dm.conn.Object("org.freedesktop.UDisks2", "/org/freedesktop/UDisks2/Manager")
	var blockDevices []dbus.ObjectPath

	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Manager.GetBlockDevices", 0,
		map[string]dbus.Variant{}).Store(&blockDevices)
	if err != nil {
		return nil, fmt.Errorf("failed to get block devices: %w", err)
	}

	var disks []*DiskInfo
	for _, devicePath := range blockDevices {
		diskInfo, err := dm.getDiskInfo(ctx, devicePath)
		if err != nil {
			dm.logger.Warn("Failed to get disk info",
				zap.String("device", string(devicePath)),
				zap.Error(err))
			continue
		}

		// Only include physical drives (not partitions)
		if diskInfo != nil && !strings.Contains(diskInfo.Device, "p") &&
			!strings.Contains(diskInfo.Device, "1") {
			disks = append(disks, diskInfo)
		}
	}

	dm.logger.Info("Discovered disks", zap.Int("count", len(disks)))
	return disks, nil
}

// CreateVolume creates a new volume on the specified device
func (dm *DiskManager) CreateVolume(ctx context.Context, req *VolumeRequest) (*VolumeInfo, error) {
	dm.logger.Info("Creating volume",
		zap.String("device", req.Device),
		zap.String("filesystem", req.Filesystem),
		zap.Uint64("size", req.Size))

	// Validate device exists and is safe to use
	if err := dm.validateDevice(ctx, req.Device); err != nil {
		return nil, fmt.Errorf("device validation failed: %w", err)
	}

	// Get device object path
	devicePath, err := dm.getDeviceObjectPath(req.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to get device object path: %w", err)
	}

	// Create partition table if needed
	if err := dm.createPartitionTable(ctx, devicePath); err != nil {
		return nil, fmt.Errorf("failed to create partition table: %w", err)
	}

	// Create partition
	partitionPath, err := dm.createPartition(ctx, devicePath, req.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to create partition: %w", err)
	}

	// Setup encryption if requested
	var finalDevicePath = partitionPath
	if req.Encrypted {
		encryptedPath, err := dm.setupEncryption(ctx, partitionPath, req.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to setup encryption: %w", err)
		}
		finalDevicePath = encryptedPath
	}

	// Create filesystem
	if err := dm.createFilesystem(ctx, finalDevicePath, req.Filesystem, req.Label); err != nil {
		return nil, fmt.Errorf("failed to create filesystem: %w", err)
	}

	// Mount if mount point specified
	var mountPoint string
	if req.MountPoint != "" {
		mountPoint, err = dm.mountVolume(ctx, finalDevicePath, req.MountPoint, req.Options)
		if err != nil {
			return nil, fmt.Errorf("failed to mount volume: %w", err)
		}
	}

	// Get volume information
	volumeInfo, err := dm.getVolumeInfo(ctx, finalDevicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get volume info: %w", err)
	}

	volumeInfo.MountPoint = mountPoint
	volumeInfo.CreatedAt = time.Now()
	volumeInfo.Metadata = req.Metadata

	dm.logger.Info("Volume created successfully",
		zap.String("device", volumeInfo.Device),
		zap.String("uuid", volumeInfo.UUID))

	return volumeInfo, nil
}

// GetDiskHealth gets comprehensive disk health information
func (dm *DiskManager) GetDiskHealth(ctx context.Context, device string) (*DiskHealth, error) {
	dm.logger.Info("Getting disk health", zap.String("device", device))

	devicePath, err := dm.getDeviceObjectPath(device)
	if err != nil {
		return nil, fmt.Errorf("failed to get device object path: %w", err)
	}

	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	// Get SMART data
	var smartData map[string]dbus.Variant
	err = obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Drive.Ata.SmartGetAttributes", 0,
		map[string]dbus.Variant{}).Store(&smartData)

	health := &DiskHealth{
		Status:    "unknown",
		SmartData: make(map[string]string),
		LastCheck: time.Now(),
	}

	if err == nil {
		// Parse SMART data
		for key, value := range smartData {
			health.SmartData[key] = fmt.Sprintf("%v", value.Value())
		}

		// Determine health status based on SMART data
		health.Status = dm.evaluateHealthStatus(health.SmartData)
	}

	// Get temperature if available
	var temp dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Drive.Ata", "SmartTemperature").Store(&temp)
	if err == nil {
		if tempVal, ok := temp.Value().(int32); ok {
			health.Temperature = int(tempVal)
		}
	}

	return health, nil
}

// ResizeVolume resizes an existing volume
func (dm *DiskManager) ResizeVolume(ctx context.Context, device string, newSize uint64) error {
	dm.logger.Info("Resizing volume",
		zap.String("device", device),
		zap.Uint64("new_size", newSize))

	devicePath, err := dm.getDeviceObjectPath(device)
	if err != nil {
		return fmt.Errorf("failed to get device object path: %w", err)
	}

	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	// Resize partition
	err = obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Partition.Resize", 0,
		newSize, map[string]dbus.Variant{}).Err
	if err != nil {
		return fmt.Errorf("failed to resize partition: %w", err)
	}

	// Resize filesystem
	err = obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Filesystem.Repair", 0,
		map[string]dbus.Variant{"resize": dbus.MakeVariant(true)}).Err
	if err != nil {
		return fmt.Errorf("failed to resize filesystem: %w", err)
	}

	dm.logger.Info("Volume resized successfully", zap.String("device", device))
	return nil
}

// MountVolume mounts a volume at the specified mount point
func (dm *DiskManager) MountVolume(ctx context.Context, device, mountPoint string, options []string) error {
	dm.logger.Info("Mounting volume",
		zap.String("device", device),
		zap.String("mount_point", mountPoint))

	devicePath, err := dm.getDeviceObjectPath(device)
	if err != nil {
		return fmt.Errorf("failed to get device object path: %w", err)
	}

	_, err = dm.mountVolume(ctx, devicePath, mountPoint, options)
	return err
}

// UnmountVolume unmounts a volume
func (dm *DiskManager) UnmountVolume(ctx context.Context, device string) error {
	dm.logger.Info("Unmounting volume", zap.String("device", device))

	devicePath, err := dm.getDeviceObjectPath(device)
	if err != nil {
		return fmt.Errorf("failed to get device object path: %w", err)
	}

	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	err = obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Filesystem.Unmount", 0,
		map[string]dbus.Variant{}).Err
	if err != nil {
		return fmt.Errorf("failed to unmount volume: %w", err)
	}

	dm.logger.Info("Volume unmounted successfully", zap.String("device", device))
	return nil
}

// Helper methods

func (dm *DiskManager) getDiskInfo(ctx context.Context, devicePath dbus.ObjectPath) (*DiskInfo, error) {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	// Get device properties
	var device, model, serial, vendor, mediaType, connectionBus string
	var size uint64
	var removable bool

	// Get device name
	var deviceVar dbus.Variant
	err := obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "Device").Store(&deviceVar)
	if err == nil {
		if deviceBytes, ok := deviceVar.Value().([]byte); ok {
			device = strings.TrimRight(string(deviceBytes), "\x00")
		}
	}

	// Get size
	var sizeVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "Size").Store(&sizeVar)
	if err == nil {
		if sizeVal, ok := sizeVar.Value().(uint64); ok {
			size = sizeVal
		}
	}

	// Get drive properties if available
	var driveVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "Drive").Store(&driveVar)
	if err == nil {
		if drivePath, ok := driveVar.Value().(dbus.ObjectPath); ok && drivePath != "/" {
			driveObj := dm.conn.Object("org.freedesktop.UDisks2", drivePath)

			// Get model
			var modelVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "Model").Store(&modelVar)
			if err == nil {
				if modelVal, ok := modelVar.Value().(string); ok {
					model = modelVal
				}
			}

			// Get vendor
			var vendorVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "Vendor").Store(&vendorVar)
			if err == nil {
				if vendorVal, ok := vendorVar.Value().(string); ok {
					vendor = vendorVal
				}
			}

			// Get serial
			var serialVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "Serial").Store(&serialVar)
			if err == nil {
				if serialVal, ok := serialVar.Value().(string); ok {
					serial = serialVal
				}
			}

			// Get media type
			var mediaVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "Media").Store(&mediaVar)
			if err == nil {
				if mediaVal, ok := mediaVar.Value().(string); ok {
					mediaType = mediaVal
				}
			}

			// Get connection bus
			var busVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "ConnectionBus").Store(&busVar)
			if err == nil {
				if busVal, ok := busVar.Value().(string); ok {
					connectionBus = busVal
				}
			}

			// Get removable
			var removableVar dbus.Variant
			err = driveObj.Call("org.freedesktop.DBus.Properties.Get", 0,
				"org.freedesktop.UDisks2.Drive", "Removable").Store(&removableVar)
			if err == nil {
				if removableVal, ok := removableVar.Value().(bool); ok {
					removable = removableVal
				}
			}
		}
	}

	if device == "" {
		return nil, nil // Skip invalid devices
	}

	return &DiskInfo{
		Device:        device,
		Size:          int64(size),
		Model:         model,
		Serial:        serial,
		Vendor:        vendor,
		MediaType:     mediaType,
		ConnectionBus: connectionBus,
		Removable:     removable,
		Metadata:      make(map[string]string),
	}, nil
}

func (dm *DiskManager) validateDevice(ctx context.Context, device string) error {
	// Check if device exists
	devicePath, err := dm.getDeviceObjectPath(device)
	if err != nil {
		return fmt.Errorf("device not found: %w", err)
	}

	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	// Check if device is mounted
	var mountPoints dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Filesystem", "MountPoints").Store(&mountPoints)
	if err == nil {
		if mounts, ok := mountPoints.Value().([][]byte); ok && len(mounts) > 0 {
			return fmt.Errorf("device %s is currently mounted", device)
		}
	}

	return nil
}

func (dm *DiskManager) getDeviceObjectPath(device string) (dbus.ObjectPath, error) {
	// Convert device name to object path
	// This is a simplified implementation - in practice you'd query udisks2
	deviceName := strings.TrimPrefix(device, "/dev/")
	objectPath := fmt.Sprintf("/org/freedesktop/UDisks2/block_devices/%s",
		strings.ReplaceAll(deviceName, "/", "_"))
	return dbus.ObjectPath(objectPath), nil
}

func (dm *DiskManager) createPartitionTable(ctx context.Context, devicePath dbus.ObjectPath) error {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Block.Format", 0,
		"gpt", map[string]dbus.Variant{}).Err
	if err != nil {
		return fmt.Errorf("failed to create GPT partition table: %w", err)
	}

	return nil
}

func (dm *DiskManager) createPartition(ctx context.Context, devicePath dbus.ObjectPath, size uint64) (dbus.ObjectPath, error) {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	var partitionPath dbus.ObjectPath
	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.PartitionTable.CreatePartition", 0,
		uint64(0), size, "", "", map[string]dbus.Variant{}).Store(&partitionPath)
	if err != nil {
		return "", fmt.Errorf("failed to create partition: %w", err)
	}

	return partitionPath, nil
}

func (dm *DiskManager) setupEncryption(ctx context.Context, devicePath dbus.ObjectPath, passphrase string) (dbus.ObjectPath, error) {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	var encryptedPath dbus.ObjectPath
	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Block.Format", 0,
		"crypto_LUKS", map[string]dbus.Variant{
			"encrypt.passphrase": dbus.MakeVariant(passphrase),
		}).Store(&encryptedPath)
	if err != nil {
		return "", fmt.Errorf("failed to setup encryption: %w", err)
	}

	// Unlock the encrypted device
	var unlockedPath dbus.ObjectPath
	err = obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Encrypted.Unlock", 0,
		passphrase, map[string]dbus.Variant{}).Store(&unlockedPath)
	if err != nil {
		return "", fmt.Errorf("failed to unlock encrypted device: %w", err)
	}

	return unlockedPath, nil
}

func (dm *DiskManager) createFilesystem(ctx context.Context, devicePath dbus.ObjectPath, fsType, label string) error {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	options := map[string]dbus.Variant{}
	if label != "" {
		options["label"] = dbus.MakeVariant(label)
	}

	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Block.Format", 0,
		fsType, options).Err
	if err != nil {
		return fmt.Errorf("failed to create %s filesystem: %w", fsType, err)
	}

	return nil
}

func (dm *DiskManager) mountVolume(ctx context.Context, devicePath dbus.ObjectPath, mountPoint string, options []string) (string, error) {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	mountOptions := map[string]dbus.Variant{}
	if mountPoint != "" {
		mountOptions["dir"] = dbus.MakeVariant(mountPoint)
	}
	if len(options) > 0 {
		mountOptions["options"] = dbus.MakeVariant(strings.Join(options, ","))
	}

	var actualMountPoint string
	err := obj.CallWithContext(ctx, "org.freedesktop.UDisks2.Filesystem.Mount", 0,
		mountOptions).Store(&actualMountPoint)
	if err != nil {
		return "", fmt.Errorf("failed to mount volume: %w", err)
	}

	return actualMountPoint, nil
}

func (dm *DiskManager) getVolumeInfo(ctx context.Context, devicePath dbus.ObjectPath) (*VolumeInfo, error) {
	obj := dm.conn.Object("org.freedesktop.UDisks2", devicePath)

	var device, uuid, fsType, label string
	var size uint64

	// Get device name
	var deviceVar dbus.Variant
	err := obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "Device").Store(&deviceVar)
	if err == nil {
		if deviceBytes, ok := deviceVar.Value().([]byte); ok {
			device = strings.TrimRight(string(deviceBytes), "\x00")
		}
	}

	// Get UUID
	var uuidVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "IdUUID").Store(&uuidVar)
	if err == nil {
		if uuidVal, ok := uuidVar.Value().(string); ok {
			uuid = uuidVal
		}
	}

	// Get filesystem type
	var fsVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "IdType").Store(&fsVar)
	if err == nil {
		if fsVal, ok := fsVar.Value().(string); ok {
			fsType = fsVal
		}
	}

	// Get label
	var labelVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "IdLabel").Store(&labelVar)
	if err == nil {
		if labelVal, ok := labelVar.Value().(string); ok {
			label = labelVal
		}
	}

	// Get size
	var sizeVar dbus.Variant
	err = obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.UDisks2.Block", "Size").Store(&sizeVar)
	if err == nil {
		if sizeVal, ok := sizeVar.Value().(uint64); ok {
			size = sizeVal
		}
	}

	return &VolumeInfo{
		Device:     device,
		UUID:       uuid,
		Size:       size,
		Filesystem: fsType,
		Label:      label,
		Status:     "ready",
		Metadata:   make(map[string]string),
	}, nil
}

func (dm *DiskManager) evaluateHealthStatus(smartData map[string]string) string {
	// Simple health evaluation based on common SMART attributes
	// In production, this would be more sophisticated

	if temp, exists := smartData["temperature"]; exists {
		if tempVal, err := strconv.Atoi(temp); err == nil && tempVal > 60 {
			return "warning"
		}
	}

	if reallocated, exists := smartData["reallocated_sector_count"]; exists {
		if count, err := strconv.Atoi(reallocated); err == nil && count > 0 {
			return "warning"
		}
	}

	if pending, exists := smartData["current_pending_sector_count"]; exists {
		if count, err := strconv.Atoi(pending); err == nil && count > 0 {
			return "critical"
		}
	}

	return "healthy"
}
