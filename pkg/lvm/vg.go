package lvm

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateVolumeGroup creates a new volume group
func CreateVolumeGroup(rc *eos_io.RuntimeContext, config *VolumeGroupConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volume group creation requirements",
		zap.String("name", config.Name),
		zap.Strings("pvs", config.PhysicalVolumes))

	// Validate inputs
	if config.Name == "" {
		return eos_err.NewUserError("volume group name is required")
	}

	if len(config.PhysicalVolumes) == 0 {
		return eos_err.NewUserError("at least one physical volume is required")
	}

	// Check if VG already exists
	checkCmd := exec.CommandContext(rc.Ctx, "vgdisplay", config.Name)
	if err := checkCmd.Run(); err == nil {
		return eos_err.NewUserError("volume group %s already exists", config.Name)
	}

	// Verify all PVs exist and are available
	for _, pv := range config.PhysicalVolumes {
		pvInfo, err := GetPhysicalVolume(rc, pv)
		if err != nil {
			return eos_err.NewUserError("physical volume %s not found: %w", pv, err)
		}

		if pvInfo.VolumeGroup != "" {
			return eos_err.NewUserError("physical volume %s is already in volume group %s",
				pv, pvInfo.VolumeGroup)
		}
	}

	// INTERVENE
	logger.Info("Creating volume group",
		zap.String("name", config.Name),
		zap.Int("pvCount", len(config.PhysicalVolumes)))

	// Build vgcreate command
	args := []string{"vgcreate", "-y"}

	if config.ExtentSize != "" {
		args = append(args, "-s", config.ExtentSize)
	}

	if config.MaxLogicalVolumes > 0 {
		args = append(args, "-l", fmt.Sprintf("%d", config.MaxLogicalVolumes))
	}

	if config.MaxPhysicalVolumes > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", config.MaxPhysicalVolumes))
	}

	args = append(args, config.Name)
	args = append(args, config.PhysicalVolumes...)

	createCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create volume group: %w, output: %s", err, string(output))
	}

	logger.Debug("Volume group created",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying volume group creation")

	// Verify VG was created
	vgInfo, err := GetVolumeGroup(rc, config.Name)
	if err != nil {
		return fmt.Errorf("volume group verification failed: %w", err)
	}

	if vgInfo.Name != config.Name {
		return fmt.Errorf("volume group verification failed: name mismatch")
	}

	// Verify all PVs are in the VG
	for _, pv := range config.PhysicalVolumes {
		found := false
		for _, vgPV := range vgInfo.PhysicalVolumes {
			if vgPV == pv {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("physical volume %s not found in volume group", pv)
		}
	}

	logger.Info("Volume group created successfully",
		zap.String("name", vgInfo.Name),
		zap.String("uuid", vgInfo.UUID),
		zap.Int64("size", vgInfo.Size),
		zap.Int64("free", vgInfo.Free))

	return nil
}

// GetVolumeGroup retrieves information about a volume group
func GetVolumeGroup(rc *eos_io.RuntimeContext, name string) (*VolumeGroup, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volume group",
		zap.String("name", name))

	// INTERVENE
	logger.Info("Reading volume group information")

	vg := &VolumeGroup{
		Name: name,
	}

	// Get detailed information using vgs
	vgsCmd := exec.CommandContext(rc.Ctx, "vgs", "--units", "b", "--noheadings", "-o",
		"vg_name,vg_uuid,vg_size,vg_free,vg_extent_size,vg_extent_count,vg_free_count,pv_count,lv_count,snap_count,vg_attr",
		"--separator", "|", name)

	output, err := vgsCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("volume group not found: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(fields) < 11 {
		return nil, fmt.Errorf("unexpected vgs output format")
	}

	vg.UUID = strings.TrimSpace(fields[1])
	vg.Attributes = strings.TrimSpace(fields[10])

	// Parse sizes
	if size, err := parseSizeBytes(fields[2]); err == nil {
		vg.Size = size
	}
	if free, err := parseSizeBytes(fields[3]); err == nil {
		vg.Free = free
	}
	vg.Used = vg.Size - vg.Free

	// Parse extent information
	if extentSize, err := parseSizeBytes(fields[4]); err == nil {
		vg.ExtentSize = extentSize
	}
	if totalExtents, err := parseIntValue(fields[5]); err == nil {
		vg.TotalExtents = totalExtents
	}
	if freeExtents, err := parseIntValue(fields[6]); err == nil {
		vg.FreeExtents = freeExtents
	}

	// Parse counts
	if snapCount, err := parseIntValue(fields[9]); err == nil {
		vg.SnapshotCount = int(snapCount)
	}

	// Get physical volumes
	pvsCmd := exec.CommandContext(rc.Ctx, "pvs", "--noheadings", "-o", "pv_name", "-S", fmt.Sprintf("vg_name=%s", name))
	if output, err := pvsCmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			pv := strings.TrimSpace(line)
			if pv != "" {
				vg.PhysicalVolumes = append(vg.PhysicalVolumes, pv)
			}
		}
	}

	// Get logical volumes
	lvsCmd := exec.CommandContext(rc.Ctx, "lvs", "--noheadings", "-o", "lv_name", "-S", fmt.Sprintf("vg_name=%s", name))
	if output, err := lvsCmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			lv := strings.TrimSpace(line)
			if lv != "" {
				vg.LogicalVolumes = append(vg.LogicalVolumes, lv)
			}
		}
	}

	// EVALUATE
	logger.Info("Volume group information retrieved",
		zap.String("name", vg.Name),
		zap.String("uuid", vg.UUID),
		zap.Int("pvCount", len(vg.PhysicalVolumes)),
		zap.Int("lvCount", len(vg.LogicalVolumes)))

	return vg, nil
}

// ExtendVolumeGroup adds physical volumes to a volume group
func ExtendVolumeGroup(rc *eos_io.RuntimeContext, vgName string, pvs []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volume group extension",
		zap.String("vg", vgName),
		zap.Strings("pvs", pvs))

	// Check if VG exists
	vg, err := GetVolumeGroup(rc, vgName)
	if err != nil {
		return eos_err.NewUserError("volume group not found: %s", vgName)
	}

	// Verify PVs exist and are available
	for _, pv := range pvs {
		pvInfo, err := GetPhysicalVolume(rc, pv)
		if err != nil {
			return eos_err.NewUserError("physical volume %s not found: %w", pv, err)
		}

		if pvInfo.VolumeGroup != "" {
			return eos_err.NewUserError("physical volume %s is already in volume group %s",
				pv, pvInfo.VolumeGroup)
		}
	}

	// INTERVENE
	logger.Info("Extending volume group",
		zap.String("vg", vgName),
		zap.Int("newPVs", len(pvs)))

	// Extend the VG
	args := append([]string{"vgextend", "-y", vgName}, pvs...)
	extendCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)

	output, err := extendCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to extend volume group: %w, output: %s", err, string(output))
	}

	logger.Debug("Volume group extended",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying volume group extension")

	// Get updated VG info
	newVG, err := GetVolumeGroup(rc, vgName)
	if err != nil {
		return fmt.Errorf("failed to verify extension: %w", err)
	}

	// Verify all new PVs are in the VG
	for _, pv := range pvs {
		found := false
		for _, vgPV := range newVG.PhysicalVolumes {
			if vgPV == pv {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("physical volume %s not found in volume group after extension", pv)
		}
	}

	logger.Info("Volume group extended successfully",
		zap.String("vg", vgName),
		zap.Int64("oldSize", vg.Size),
		zap.Int64("newSize", newVG.Size),
		zap.Int64("sizeDiff", newVG.Size-vg.Size))

	return nil
}

// ReduceVolumeGroup removes physical volumes from a volume group
func ReduceVolumeGroup(rc *eos_io.RuntimeContext, vgName string, pvs []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volume group reduction",
		zap.String("vg", vgName),
		zap.Strings("pvs", pvs))

	// Check if VG exists
	vg, err := GetVolumeGroup(rc, vgName)
	if err != nil {
		return eos_err.NewUserError("volume group not found: %s", vgName)
	}

	// Verify PVs are part of the VG
	for _, pv := range pvs {
		found := false
		for _, vgPV := range vg.PhysicalVolumes {
			if vgPV == pv {
				found = true
				break
			}
		}
		if !found {
			return eos_err.NewUserError("physical volume %s is not in volume group %s", pv, vgName)
		}
	}

	// Check if removing PVs would leave at least one PV
	if len(vg.PhysicalVolumes)-len(pvs) < 1 {
		return eos_err.NewUserError("cannot remove all physical volumes from volume group")
	}

	// Check if PVs have allocated extents
	for _, pv := range pvs {
		checkCmd := exec.CommandContext(rc.Ctx, "pvs", "--noheadings", "-o", "pv_pe_alloc_count", pv)
		if output, err := checkCmd.Output(); err == nil {
			if allocCount, err := parseIntValue(string(output)); err == nil && allocCount > 0 {
				return eos_err.NewUserError("physical volume %s has %d allocated extents. Move data first with pvmove",
					pv, allocCount)
			}
		}
	}

	// INTERVENE
	logger.Info("Reducing volume group",
		zap.String("vg", vgName),
		zap.Int("removePVs", len(pvs)))

	// Reduce the VG
	args := append([]string{"vgreduce", "-y", vgName}, pvs...)
	reduceCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)

	output, err := reduceCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reduce volume group: %w, output: %s", err, string(output))
	}

	logger.Debug("Volume group reduced",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying volume group reduction")

	// Get updated VG info
	newVG, err := GetVolumeGroup(rc, vgName)
	if err != nil {
		return fmt.Errorf("failed to verify reduction: %w", err)
	}

	// Verify PVs were removed
	for _, pv := range pvs {
		for _, vgPV := range newVG.PhysicalVolumes {
			if vgPV == pv {
				return fmt.Errorf("physical volume %s still in volume group after reduction", pv)
			}
		}
	}

	logger.Info("Volume group reduced successfully",
		zap.String("vg", vgName),
		zap.Int64("oldSize", vg.Size),
		zap.Int64("newSize", newVG.Size),
		zap.Int("pvCount", len(newVG.PhysicalVolumes)))

	return nil
}

// RemoveVolumeGroup removes a volume group
func RemoveVolumeGroup(rc *eos_io.RuntimeContext, name string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volume group for removal",
		zap.String("name", name))

	// Check if VG exists
	vg, err := GetVolumeGroup(rc, name)
	if err != nil {
		return eos_err.NewUserError("volume group not found: %s", name)
	}

	// Check if VG has logical volumes
	if len(vg.LogicalVolumes) > 0 && !force {
		return eos_err.NewUserError("volume group %s has %d logical volumes. Remove them first or use --force",
			name, len(vg.LogicalVolumes))
	}

	// INTERVENE
	logger.Info("Removing volume group",
		zap.String("name", name),
		zap.Bool("force", force))

	// If force and has LVs, remove them first
	if force && len(vg.LogicalVolumes) > 0 {
		logger.Debug("Force removing logical volumes")
		for _, lv := range vg.LogicalVolumes {
			removeCmd := exec.CommandContext(rc.Ctx, "lvremove", "-y", "-f", fmt.Sprintf("%s/%s", name, lv))
			if output, err := removeCmd.CombinedOutput(); err != nil {
				logger.Warn("Failed to remove logical volume",
					zap.String("lv", lv),
					zap.Error(err),
					zap.String("output", string(output)))
			}
		}
	}

	// Remove the VG
	args := []string{"vgremove", "-y"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)

	removeCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := removeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove volume group: %w, output: %s", err, string(output))
	}

	// EVALUATE
	logger.Info("Verifying volume group removal")

	// Verify VG was removed
	checkCmd := exec.CommandContext(rc.Ctx, "vgdisplay", name)
	if err := checkCmd.Run(); err == nil {
		return fmt.Errorf("volume group removal verification failed: VG still exists")
	}

	logger.Info("Volume group removed successfully",
		zap.String("name", name))

	return nil
}
