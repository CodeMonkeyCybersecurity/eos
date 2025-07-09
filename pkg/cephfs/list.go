package cephfs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListVolumes lists all CephFS volumes
func ListVolumes(rc *eos_io.RuntimeContext) ([]*VolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing CephFS for volume listing")

	// Check if ceph command is available
	if _, err := eos_cli.LookPath("ceph"); err != nil {
		return nil, eos_err.NewUserError("ceph command not found. Please install ceph-common package")
	}

	// INTERVENE
	logger.Info("Listing CephFS volumes")

	// Get list of filesystems
	listCmd := eos_cli.Wrap(rc, "ceph", "fs", "ls", "--format", "json")
	output, err := listCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	var fsList []struct {
		Name      string   `json:"name"`
		Metadata  string   `json:"metadata_pool"`
		DataPools []string `json:"data_pools"`
	}

	if err := json.Unmarshal(output, &fsList); err != nil {
		return nil, fmt.Errorf("failed to parse volume list: %w", err)
	}

	volumes := make([]*VolumeInfo, 0, len(fsList))

	// Get detailed info for each volume
	for _, fs := range fsList {
		logger.Debug("Getting details for volume",
			zap.String("volume", fs.Name))

		info, err := ReadVolumeInfo(rc, fs.Name)
		if err != nil {
			logger.Warn("Failed to get volume details",
				zap.String("volume", fs.Name),
				zap.Error(err))

			// Create basic info if detailed read fails
			info = &VolumeInfo{
				Name:          fs.Name,
				MetadataPools: []string{fs.Metadata},
				DataPools:     fs.DataPools,
			}
		}

		volumes = append(volumes, info)
	}

	// EVALUATE
	logger.Info("Volume listing completed",
		zap.Int("volumeCount", len(volumes)))

	return volumes, nil
}

// ListMounts lists all CephFS mount points
func ListMounts(rc *eos_io.RuntimeContext) ([]*MountInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing system for CephFS mounts")

	// INTERVENE
	logger.Info("Listing CephFS mount points")

	// Find all CephFS mounts
	findmntCmd := eos_cli.Wrap(rc, "findmnt", "-t", "ceph", "-J")
	output, err := findmntCmd.Output()
	if err != nil {
		// No CephFS mounts found
		logger.Debug("No CephFS mounts found")
		return []*MountInfo{}, nil
	}

	var result struct {
		Filesystems []struct {
			Target  string `json:"target"`
			Source  string `json:"source"`
			Fstype  string `json:"fstype"`
			Options string `json:"options"`
		} `json:"filesystems"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse mount list: %w", err)
	}

	mounts := make([]*MountInfo, 0, len(result.Filesystems))

	for _, fs := range result.Filesystems {
		mount := &MountInfo{
			Device:     fs.Source,
			MountPoint: fs.Target,
			FileSystem: fs.Fstype,
			Options:    strings.Split(fs.Options, ","),
			IsActive:   true,
		}

		mounts = append(mounts, mount)

		logger.Debug("Found CephFS mount",
			zap.String("mountPoint", mount.MountPoint),
			zap.String("device", mount.Device))
	}

	// EVALUATE
	logger.Info("Mount listing completed",
		zap.Int("mountCount", len(mounts)))

	return mounts, nil
}

// ListPools lists all Ceph pools used by CephFS
func ListPools(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Ceph for pool listing")

	// INTERVENE
	logger.Info("Listing Ceph pools")

	// Get all pools
	poolCmd := eos_cli.Wrap(rc, "ceph", "osd", "pool", "ls", "detail", "--format", "json")
	output, err := poolCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list pools: %w", err)
	}

	var pools []map[string]interface{}
	if err := json.Unmarshal(output, &pools); err != nil {
		return nil, fmt.Errorf("failed to parse pool list: %w", err)
	}

	// Filter CephFS-related pools
	cephfsPools := make(map[string]interface{})

	for _, pool := range pools {
		poolName, _ := pool["pool_name"].(string)

		// Check if pool has cephfs application enabled
		if apps, ok := pool["application_metadata"].(map[string]interface{}); ok {
			if _, hasCephFS := apps["cephfs"]; hasCephFS {
				cephfsPools[poolName] = pool

				logger.Debug("Found CephFS pool",
					zap.String("pool", poolName))
			}
		}
	}

	// EVALUATE
	logger.Info("Pool listing completed",
		zap.Int("cephfsPoolCount", len(cephfsPools)),
		zap.Int("totalPoolCount", len(pools)))

	return cephfsPools, nil
}
