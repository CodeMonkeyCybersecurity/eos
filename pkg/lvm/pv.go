package lvm

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreatePhysicalVolume creates a new LVM physical volume
func CreatePhysicalVolume(rc *eos_io.RuntimeContext, config *PhysicalVolumeConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing device for physical volume creation",
		zap.String("device", config.Device))

	// Check if device exists
	if _, err := os.Stat(config.Device); err != nil {
		return eos_err.NewUserError("device not found: %s", config.Device)
	}

	// Check if device is already a PV
	checkCmd := eos_cli.Wrap(rc, "pvdisplay", config.Device)
	if err := checkCmd.Run(); err == nil {
		if !config.Force {
			return eos_err.NewUserError("device %s is already an LVM physical volume. Use --force to overwrite", config.Device)
		}
		logger.Warn("Device is already a physical volume, will overwrite",
			zap.String("device", config.Device))
	}

	// Check if device is mounted
	if isMounted, mountPoint := isDeviceMounted(rc, config.Device); isMounted {
		return eos_err.NewUserError("device %s is mounted at %s. Please unmount before creating PV",
			config.Device, mountPoint)
	}

	// Check for existing filesystem
	if !config.Force {
		if hasFilesystem, fsType := deviceHasFilesystem(rc, config.Device); hasFilesystem {
			return eos_err.NewUserError("device %s contains a %s filesystem. Use --force to overwrite",
				config.Device, fsType)
		}
	}

	// INTERVENE
	logger.Info("Creating physical volume",
		zap.String("device", config.Device),
		zap.Bool("force", config.Force))

	// Build pvcreate command
	args := []string{"pvcreate", "-y"}

	if config.Force {
		args = append(args, "-f")
	}

	if config.UUID != "" {
		args = append(args, "-u", config.UUID)
	}

	if config.DataAlignment != "" {
		args = append(args, "--dataalignment", config.DataAlignment)
	}

	if config.MetadataSize != "" {
		args = append(args, "--metadatasize", config.MetadataSize)
	}

	args = append(args, config.Device)

	createCmd := eos_cli.Wrap(rc, args[0], args[1:]...)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create physical volume: %w, output: %s", err, string(output))
	}

	logger.Debug("Physical volume created",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying physical volume creation")

	// Verify PV was created
	pvInfo, err := GetPhysicalVolume(rc, config.Device)
	if err != nil {
		return fmt.Errorf("physical volume verification failed: %w", err)
	}

	if pvInfo.Device != config.Device {
		return fmt.Errorf("physical volume verification failed: device mismatch")
	}

	logger.Info("Physical volume created successfully",
		zap.String("device", pvInfo.Device),
		zap.String("uuid", pvInfo.UUID),
		zap.Int64("sizeBytes", pvInfo.Size))

	return nil
}

// GetPhysicalVolume retrieves information about a physical volume
func GetPhysicalVolume(rc *eos_io.RuntimeContext, device string) (*PhysicalVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing physical volume",
		zap.String("device", device))

	// INTERVENE
	logger.Info("Reading physical volume information")

	// Use pvdisplay with separator for parsing
	displayCmd := eos_cli.Wrap(rc, "pvdisplay", "-C", "--noheadings", "--separator", "|", device)
	output, err := displayCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("physical volume not found: %w", err)
	}

	// Parse output
	fields := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(fields) < 11 {
		return nil, fmt.Errorf("unexpected pvdisplay output format")
	}

	pv := &PhysicalVolume{
		Device:      strings.TrimSpace(fields[0]),
		VolumeGroup: strings.TrimSpace(fields[1]),
		Attributes:  strings.TrimSpace(fields[8]),
	}

	// Get detailed information using pvs
	pvsCmd := eos_cli.Wrap(rc, "pvs", "--units", "b", "--noheadings", "-o",
		"pv_name,pv_uuid,pv_size,pv_free,pv_used,pv_pe_count,pv_pe_alloc_count,pe_start",
		"--separator", "|", device)

	if output, err := pvsCmd.Output(); err == nil {
		fields := strings.Split(strings.TrimSpace(string(output)), "|")
		if len(fields) >= 8 {
			pv.UUID = strings.TrimSpace(fields[1])

			// Parse sizes (remove 'B' suffix)
			if size, err := parseSizeBytes(fields[2]); err == nil {
				pv.Size = size
			}
			if free, err := parseSizeBytes(fields[3]); err == nil {
				pv.Free = free
			}
			if used, err := parseSizeBytes(fields[4]); err == nil {
				pv.Used = used
			}

			// Parse extent information
			if peCount, err := parseIntValue(fields[5]); err == nil {
				pv.TotalExtents = peCount
			}
			if peAlloc, err := parseIntValue(fields[6]); err == nil {
				pv.FreeExtents = pv.TotalExtents - peAlloc
			}

			// Calculate extent size
			if pv.TotalExtents > 0 {
				pv.ExtentSize = pv.Size / pv.TotalExtents
			}
		}
	}

	// Check if allocatable
	pv.Allocatable = !strings.Contains(pv.Attributes, "x")

	// EVALUATE
	logger.Info("Physical volume information retrieved",
		zap.String("device", pv.Device),
		zap.String("uuid", pv.UUID),
		zap.Int64("size", pv.Size),
		zap.Int64("free", pv.Free))

	return pv, nil
}

// ListPhysicalVolumes lists all physical volumes
func ListPhysicalVolumes(rc *eos_io.RuntimeContext) ([]*PhysicalVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing system for physical volumes")

	// INTERVENE
	logger.Info("Listing physical volumes")

	// Get list of all PVs
	pvsCmd := eos_cli.Wrap(rc, "pvs", "--noheadings", "-o", "pv_name", "--separator", " ")
	output, err := pvsCmd.Output()
	if err != nil {
		logger.Debug("No physical volumes found")
		return []*PhysicalVolume{}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	volumes := make([]*PhysicalVolume, 0, len(lines))

	for _, line := range lines {
		device := strings.TrimSpace(line)
		if device == "" {
			continue
		}

		pv, err := GetPhysicalVolume(rc, device)
		if err != nil {
			logger.Warn("Failed to get physical volume details",
				zap.String("device", device),
				zap.Error(err))
			continue
		}

		volumes = append(volumes, pv)
	}

	// EVALUATE
	logger.Info("Physical volume listing completed",
		zap.Int("count", len(volumes)))

	return volumes, nil
}

// RemovePhysicalVolume removes a physical volume
func RemovePhysicalVolume(rc *eos_io.RuntimeContext, device string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing physical volume for removal",
		zap.String("device", device))

	// Check if PV exists
	pv, err := GetPhysicalVolume(rc, device)
	if err != nil {
		return eos_err.NewUserError("physical volume not found: %s", device)
	}

	// Check if PV is part of a VG
	if pv.VolumeGroup != "" && !force {
		return eos_err.NewUserError("physical volume %s is part of volume group %s. Use --force to remove anyway",
			device, pv.VolumeGroup)
	}

	// Check if PV has allocated extents
	if pv.FreeExtents < pv.TotalExtents && !force {
		allocatedExtents := pv.TotalExtents - pv.FreeExtents
		return eos_err.NewUserError("physical volume %s has %d allocated extents. Move data or use --force",
			device, allocatedExtents)
	}

	// INTERVENE
	logger.Info("Removing physical volume",
		zap.String("device", device),
		zap.Bool("force", force))

	// If part of VG, remove from VG first
	if pv.VolumeGroup != "" {
		logger.Debug("Removing PV from volume group",
			zap.String("vg", pv.VolumeGroup))

		vgReduceCmd := eos_cli.Wrap(rc, "vgreduce", pv.VolumeGroup, device)
		if output, err := vgReduceCmd.CombinedOutput(); err != nil && !force {
			return fmt.Errorf("failed to remove PV from volume group: %w, output: %s", err, string(output))
		}
	}

	// Remove the PV
	args := []string{"pvremove", "-y"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, device)

	removeCmd := eos_cli.Wrap(rc, args[0], args[1:]...)
	output, err := removeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove physical volume: %w, output: %s", err, string(output))
	}

	// EVALUATE
	logger.Info("Verifying physical volume removal")

	// Verify PV was removed
	checkCmd := eos_cli.Wrap(rc, "pvdisplay", device)
	if err := checkCmd.Run(); err == nil {
		return fmt.Errorf("physical volume removal verification failed: PV still exists")
	}

	logger.Info("Physical volume removed successfully",
		zap.String("device", device))

	return nil
}

// ResizePhysicalVolume resizes a physical volume
func ResizePhysicalVolume(rc *eos_io.RuntimeContext, device string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing physical volume for resize",
		zap.String("device", device))

	// Check if PV exists
	pv, err := GetPhysicalVolume(rc, device)
	if err != nil {
		return eos_err.NewUserError("physical volume not found: %s", device)
	}

	oldSize := pv.Size

	// INTERVENE
	logger.Info("Resizing physical volume",
		zap.String("device", device),
		zap.Int64("currentSize", oldSize))

	// Resize the PV
	resizeCmd := eos_cli.Wrap(rc, "pvresize", device)
	output, err := resizeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to resize physical volume: %w, output: %s", err, string(output))
	}

	logger.Debug("Resize output",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying physical volume resize")

	// Get new size
	newPV, err := GetPhysicalVolume(rc, device)
	if err != nil {
		return fmt.Errorf("failed to verify resize: %w", err)
	}

	if newPV.Size == oldSize {
		logger.Warn("Physical volume size unchanged",
			zap.String("device", device),
			zap.Int64("size", newPV.Size))
	} else {
		logger.Info("Physical volume resized successfully",
			zap.String("device", device),
			zap.Int64("oldSize", oldSize),
			zap.Int64("newSize", newPV.Size),
			zap.Int64("sizeDiff", newPV.Size-oldSize))
	}

	return nil
}

// Helper functions

func isDeviceMounted(rc *eos_io.RuntimeContext, device string) (bool, string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if device is mounted
	findmntCmd := eos_cli.Wrap(rc, "findmnt", "-n", "-o", "TARGET", device)
	output, err := findmntCmd.Output()
	if err != nil {
		logger.Debug("Device not mounted",
			zap.String("device", device))
		return false, ""
	}

	mountPoint := strings.TrimSpace(string(output))
	logger.Debug("Device is mounted",
		zap.String("device", device),
		zap.String("mountPoint", mountPoint))

	return true, mountPoint
}

func deviceHasFilesystem(rc *eos_io.RuntimeContext, device string) (bool, string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use blkid to check for filesystem
	blkidCmd := eos_cli.Wrap(rc, "blkid", "-o", "value", "-s", "TYPE", device)
	output, err := blkidCmd.Output()
	if err != nil {
		logger.Debug("No filesystem detected on device",
			zap.String("device", device))
		return false, ""
	}

	fsType := strings.TrimSpace(string(output))
	if fsType != "" {
		logger.Debug("Filesystem detected on device",
			zap.String("device", device),
			zap.String("type", fsType))
		return true, fsType
	}

	return false, ""
}

func parseSizeBytes(sizeStr string) (int64, error) {
	// Remove 'B' suffix and convert to int64
	sizeStr = strings.TrimSpace(strings.TrimSuffix(sizeStr, "B"))

	var size int64
	_, err := fmt.Sscanf(sizeStr, "%d", &size)
	return size, err
}

func parseIntValue(str string) (int64, error) {
	str = strings.TrimSpace(str)

	var value int64
	_, err := fmt.Sscanf(str, "%d", &value)
	return value, err
}
