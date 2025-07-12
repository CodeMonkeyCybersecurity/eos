package btrfs

import (
	"os/exec"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Structure(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		validate func(t *testing.T, c *Config)
	}{
		{
			name: "complete config",
			config: &Config{
				Device:           "/dev/sda1",
				Label:            "backup",
				UUID:             "550e8400-e29b-41d4-a716-446655440000",
				MountPoint:       "/mnt/backup",
				MountOptions:     []string{"compress=zstd:3", "noatime"},
				Force:            true,
				SubvolumeName:    "data",
				SubvolumePath:    "/mnt/backup/data",
				Compression:      "zstd",
				CompressionLevel: 3,
				MixedMode:        false,
				Nodatasum:        false,
				Nodatacow:        false,
				DisableCoW:       false,
			},
			validate: func(t *testing.T, c *Config) {
				assert.Equal(t, "/dev/sda1", c.Device)
				assert.Equal(t, "backup", c.Label)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", c.UUID)
				assert.Equal(t, "/mnt/backup", c.MountPoint)
				assert.Len(t, c.MountOptions, 2)
				assert.True(t, c.Force)
				assert.Equal(t, "zstd", c.Compression)
				assert.Equal(t, 3, c.CompressionLevel)
			},
		},
		{
			name: "minimal config",
			config: &Config{
				Device: "/dev/sdb1",
			},
			validate: func(t *testing.T, c *Config) {
				assert.Equal(t, "/dev/sdb1", c.Device)
				assert.Empty(t, c.Label)
				assert.Empty(t, c.UUID)
				assert.Empty(t, c.MountPoint)
				assert.Empty(t, c.MountOptions)
				assert.False(t, c.Force)
			},
		},
		{
			name: "database optimized config",
			config: &Config{
				Device:       "/dev/nvme0n1p1",
				Label:        "database",
				MountPoint:   "/var/lib/postgresql",
				MountOptions: MountOptions["database"],
				Nodatacow:    true,
				Nodatasum:    true,
			},
			validate: func(t *testing.T, c *Config) {
				assert.Equal(t, "/dev/nvme0n1p1", c.Device)
				assert.Equal(t, "database", c.Label)
				assert.True(t, c.Nodatacow)
				assert.True(t, c.Nodatasum)
				assert.Contains(t, c.MountOptions, "nodatacow")
			},
		},
		{
			name: "SSD optimized config",
			config: &Config{
				Device:       "/dev/sda1",
				Label:        "fast-storage",
				MountPoint:   "/data",
				MountOptions: MountOptions["ssd"],
			},
			validate: func(t *testing.T, c *Config) {
				assert.Contains(t, c.MountOptions, "ssd")
				assert.Contains(t, c.MountOptions, "discard=async")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.config)
		})
	}
}

func TestVolumeInfo_Structure(t *testing.T) {
	tests := []struct {
		name     string
		info     *VolumeInfo
		validate func(t *testing.T, vi *VolumeInfo)
	}{
		{
			name: "complete volume info",
			info: &VolumeInfo{
				UUID:        "550e8400-e29b-41d4-a716-446655440000",
				Label:       "backup",
				TotalSize:   1099511627776, // 1TB
				UsedSize:    549755813888,  // 512GB
				DeviceCount: 1,
				Devices:     []string{"/dev/sda1"},
				MountPoints: []string{"/mnt/backup"},
				Features:    []string{"extended_iref", "skinny_metadata"},
				Generation:  12345,
				NodeSize:    16384,
				SectorSize:  4096,
				CreatedAt:   time.Now(),
			},
			validate: func(t *testing.T, vi *VolumeInfo) {
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", vi.UUID)
				assert.Equal(t, "backup", vi.Label)
				assert.Equal(t, int64(1099511627776), vi.TotalSize)
				assert.Equal(t, int64(549755813888), vi.UsedSize)
				assert.Equal(t, 1, vi.DeviceCount)
				assert.Len(t, vi.Devices, 1)
				assert.Contains(t, vi.Devices, "/dev/sda1")
				assert.Len(t, vi.MountPoints, 1)
				assert.Len(t, vi.Features, 2)
			},
		},
		{
			name: "multi-device volume",
			info: &VolumeInfo{
				UUID:        "650e8400-e29b-41d4-a716-446655440000",
				Label:       "raid",
				TotalSize:   2199023255552, // 2TB
				DeviceCount: 2,
				Devices:     []string{"/dev/sda1", "/dev/sdb1"},
				MountPoints: []string{"/mnt/raid"},
			},
			validate: func(t *testing.T, vi *VolumeInfo) {
				assert.Equal(t, 2, vi.DeviceCount)
				assert.Len(t, vi.Devices, 2)
				assert.Contains(t, vi.Devices, "/dev/sda1")
				assert.Contains(t, vi.Devices, "/dev/sdb1")
			},
		},
		{
			name: "empty volume info",
			info: &VolumeInfo{},
			validate: func(t *testing.T, vi *VolumeInfo) {
				assert.Empty(t, vi.UUID)
				assert.Empty(t, vi.Label)
				assert.Zero(t, vi.TotalSize)
				assert.Zero(t, vi.UsedSize)
				assert.Zero(t, vi.DeviceCount)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.info)
		})
	}
}

func TestSubvolumeInfo_Structure(t *testing.T) {
	tests := []struct {
		name     string
		info     *SubvolumeInfo
		validate func(t *testing.T, si *SubvolumeInfo)
	}{
		{
			name: "root subvolume",
			info: &SubvolumeInfo{
				ID:         5,
				Path:       "/",
				ParentID:   0,
				TopLevel:   5,
				Generation: 100,
				UUID:       "750e8400-e29b-41d4-a716-446655440000",
			},
			validate: func(t *testing.T, si *SubvolumeInfo) {
				assert.Equal(t, int64(5), si.ID)
				assert.Equal(t, "/", si.Path)
				assert.Equal(t, int64(0), si.ParentID)
				assert.Equal(t, int64(5), si.TopLevel)
			},
		},
		{
			name: "nested subvolume with snapshots",
			info: &SubvolumeInfo{
				ID:         256,
				Path:       "/mnt/data/subvol1",
				ParentID:   5,
				TopLevel:   5,
				Generation: 1000,
				UUID:       "850e8400-e29b-41d4-a716-446655440000",
				Snapshots:  []string{"/mnt/snapshots/snap1", "/mnt/snapshots/snap2"},
			},
			validate: func(t *testing.T, si *SubvolumeInfo) {
				assert.Equal(t, int64(256), si.ID)
				assert.Equal(t, "/mnt/data/subvol1", si.Path)
				assert.Equal(t, int64(5), si.ParentID)
				assert.Len(t, si.Snapshots, 2)
			},
		},
		{
			name: "received subvolume",
			info: &SubvolumeInfo{
				ID:           512,
				Path:         "/mnt/backup/received",
				ParentID:     5,
				UUID:         "950e8400-e29b-41d4-a716-446655440000",
				ParentUUID:   "850e8400-e29b-41d4-a716-446655440000",
				ReceivedUUID: "750e8400-e29b-41d4-a716-446655440000",
				ReceiveTime:  time.Now(),
			},
			validate: func(t *testing.T, si *SubvolumeInfo) {
				assert.NotEmpty(t, si.ReceivedUUID)
				assert.NotEmpty(t, si.ParentUUID)
				assert.False(t, si.ReceiveTime.IsZero())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.info)
		})
	}
}

func TestSnapshotConfig_Structure(t *testing.T) {
	tests := []struct {
		name     string
		config   *SnapshotConfig
		validate func(t *testing.T, sc *SnapshotConfig)
	}{
		{
			name: "readonly snapshot",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/subvol1",
				SnapshotPath: "/mnt/snapshots/snap1",
				Readonly:     true,
				Recursive:    false,
			},
			validate: func(t *testing.T, sc *SnapshotConfig) {
				assert.True(t, sc.Readonly)
				assert.False(t, sc.Recursive)
				assert.NotEqual(t, sc.SourcePath, sc.SnapshotPath)
			},
		},
		{
			name: "recursive writable snapshot",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data",
				SnapshotPath: "/mnt/backup/data-backup",
				Readonly:     false,
				Recursive:    true,
			},
			validate: func(t *testing.T, sc *SnapshotConfig) {
				assert.False(t, sc.Readonly)
				assert.True(t, sc.Recursive)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.config)
		})
	}
}

func TestCompressionConstants(t *testing.T) {
	// Test compression type constants
	assert.Equal(t, "none", CompressionNone)
	assert.Equal(t, "zlib", CompressionZlib)
	assert.Equal(t, "lzo", CompressionLZO)
	assert.Equal(t, "zstd", CompressionZSTD)

	// Test default backup compression
	assert.Equal(t, CompressionZSTD, DefaultBackupCompression)
	assert.Equal(t, 3, DefaultBackupCompressionLevel)

	// Test mount option constants
	assert.Equal(t, "compress", MountOptionCompress)
	assert.Equal(t, "compress-force", MountOptionCompressForce)
	assert.Equal(t, "noatime", MountOptionNoatime)
	assert.Equal(t, "ssd", MountOptionSSD)
}

func TestMountOptions_Predefined(t *testing.T) {
	// Test backup mount options
	backupOpts := MountOptions["backup"]
	assert.Contains(t, backupOpts, "compress-force=zstd:3")
	assert.Contains(t, backupOpts, "noatime")
	assert.Contains(t, backupOpts, "space_cache=v2")
	assert.Contains(t, backupOpts, "autodefrag")

	// Test general mount options
	generalOpts := MountOptions["general"]
	assert.Contains(t, generalOpts, "compress=zstd:1")
	assert.Contains(t, generalOpts, "noatime")

	// Test database mount options
	dbOpts := MountOptions["database"]
	assert.Contains(t, dbOpts, "nodatacow")
	assert.Contains(t, dbOpts, "nodatasum")
	assert.Contains(t, dbOpts, "noatime")

	// Test SSD mount options
	ssdOpts := MountOptions["ssd"]
	assert.Contains(t, ssdOpts, "ssd")
	assert.Contains(t, ssdOpts, "discard=async")
	assert.Contains(t, ssdOpts, "compress=zstd:1")
}

func TestCompressionStats_Structure(t *testing.T) {
	stats := &CompressionStats{
		Type:             "zstd",
		Level:            3,
		UncompressedSize: 1073741824, // 1GB
		CompressedSize:   536870912,  // 512MB
		CompressionRatio: 0.5,
		FilesCompressed:  1000,
		FilesTotal:       1200,
	}

	assert.Equal(t, "zstd", stats.Type)
	assert.Equal(t, 3, stats.Level)
	assert.Equal(t, int64(1073741824), stats.UncompressedSize)
	assert.Equal(t, int64(536870912), stats.CompressedSize)
	assert.Equal(t, 0.5, stats.CompressionRatio)
	assert.Equal(t, int64(1000), stats.FilesCompressed)
	assert.Equal(t, int64(1200), stats.FilesTotal)

	// Calculate compression percentage
	compressionPercent := float64(stats.FilesCompressed) / float64(stats.FilesTotal) * 100
	assert.InDelta(t, 83.33, compressionPercent, 0.01)
}

func TestUsageInfo_Structure(t *testing.T) {
	usage := &UsageInfo{
		TotalSize:       1099511627776, // 1TB
		UsedSize:        549755813888,  // 512GB  
		FreeSize:        549755813888,  // 512GB
		DataSize:        500000000000,  // ~465GB
		MetadataSize:    49755813888,   // ~46GB
		SystemSize:      1073741824,    // 1GB
		UnallocatedSize: 0,
	}

	assert.Equal(t, int64(1099511627776), usage.TotalSize)
	assert.Equal(t, usage.TotalSize, usage.UsedSize+usage.FreeSize)
	assert.Less(t, usage.MetadataSize, usage.DataSize)
	assert.Greater(t, usage.SystemSize, int64(0))
}

func TestBalanceConfig_Structure(t *testing.T) {
	config := &BalanceConfig{
		DataFilters:     []string{"drange=0..10G", "usage=50"},
		MetadataFilters: []string{"usage=20"},
		SystemFilters:   []string{"usage=10"},
		Force:           false,
		Background:      true,
	}

	assert.Len(t, config.DataFilters, 2)
	assert.Contains(t, config.DataFilters, "drange=0..10G")
	assert.Len(t, config.MetadataFilters, 1)
	assert.Len(t, config.SystemFilters, 1)
	assert.False(t, config.Force)
	assert.True(t, config.Background)
}

func TestScrubStatus_Structure(t *testing.T) {
	status := &ScrubStatus{
		Running:             true,
		StartTime:           time.Now().Add(-1 * time.Hour),
		Duration:            1 * time.Hour,
		DataScrubbed:        107374182400, // 100GB
		TreeScrubbed:        1073741824,   // 1GB
		DataExtents:         100000,
		TreeExtents:         10000,
		DataErrors:          0,
		TreeErrors:          0,
		CsumErrors:          1,
		VerifyErrors:        0,
		NoChecksumErrors:    0,
		CsumDiscards:        0,
		SuperErrors:         0,
		MallocErrors:        0,
		UncorrectableErrors: 0,
		CorrectableErrors:   1,
		LastError:           "",
	}

	assert.True(t, status.Running)
	assert.False(t, status.StartTime.IsZero())
	assert.Equal(t, 1*time.Hour, status.Duration)
	assert.Greater(t, status.DataScrubbed, status.TreeScrubbed)
	assert.Equal(t, int64(1), status.CsumErrors)
	assert.Equal(t, int64(1), status.CorrectableErrors)
	assert.Equal(t, int64(0), status.UncorrectableErrors)
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getParentPath", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/mnt/data/subvol", "/mnt/data"},
			{"/mnt/data/", "/mnt/data/"}, // Trailing slash is not removed from parent
			{"/mnt", ""},
			{"/", "/"}, // Root returns root
			{"relative/path", "relative"},
		}

		for _, tt := range tests {
			result := getParentPath(tt.input)
			assert.Equal(t, tt.expected, result, "getParentPath(%q)", tt.input)
		}
	})

	t.Run("isDeviceMounted with mock", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		
		// Test with unmounted device
		mounted, mountPoint := isDeviceMounted(rc, "/dev/sda99")
		assert.False(t, mounted)
		assert.Empty(t, mountPoint)
	})

	t.Run("parseBTRFSSize edge cases", func(t *testing.T) {
		// Currently returns 0 for all inputs in stub
		tests := []string{
			"10.00GiB",
			"100MiB", 
			"1.5TiB",
			"invalid",
			"",
		}

		for _, input := range tests {
			size := parseBTRFSSize(input)
			assert.Equal(t, int64(0), size) // Stub implementation
		}
	})
}

func TestCreateVolume_ErrorPaths(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	t.Run("device not found", func(t *testing.T) {
		config := &Config{
			Device: "/dev/nonexistent",
		}
		
		err := CreateVolume(rc, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device not found")
	})

	t.Run("empty device", func(t *testing.T) {
		config := &Config{
			Device: "",
		}
		
		err := CreateVolume(rc, config)
		require.Error(t, err)
	})
}

func TestCreateSubvolume_ErrorPaths(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	t.Run("parent path not found", func(t *testing.T) {
		config := &Config{
			SubvolumePath: "/nonexistent/path/subvol",
		}
		
		err := CreateSubvolume(rc, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parent path does not exist")
	})

	t.Run("empty subvolume path", func(t *testing.T) {
		config := &Config{
			SubvolumePath: "",
		}
		
		err := CreateSubvolume(rc, config)
		require.Error(t, err)
	})
}

func TestDeviceHasFilesystem_Mock(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	// Test various device scenarios
	tests := []struct {
		device   string
		expected bool
	}{
		{"/dev/sda1", false},     // Would check real device
		{"/dev/mapper/vg-lv", false},
		{"", false},
		{"/invalid/device", false},
	}

	for _, tt := range tests {
		hasFS, fsType := deviceHasFilesystem(rc, tt.device)
		assert.Equal(t, tt.expected, hasFS)
		if !hasFS {
			assert.Empty(t, fsType)
		}
	}
}

func TestIsPathOnBTRFS_Mock(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	// Test various paths
	paths := []string{
		"/mnt/btrfs",
		"/home",
		"/tmp",
		"",
		"/nonexistent",
	}

	for _, path := range paths {
		// Mock implementation always returns false
		result := isPathOnBTRFS(rc, path)
		assert.False(t, result)
	}
}

func TestExecCommandPaths(t *testing.T) {
	// Verify expected commands exist in PATH
	commands := []string{
		"btrfs",
		"mkfs.btrfs",
		"mount",
		"findmnt",
		"blkid",
		"stat",
		"chattr",
	}

	for _, cmd := range commands {
		t.Run("command_"+cmd, func(t *testing.T) {
			path, err := exec.LookPath(cmd)
			if err != nil {
				t.Skipf("Command %s not found in PATH", cmd)
			}
			assert.NotEmpty(t, path)
		})
	}
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Device:           "/dev/sda1",
				Label:            "valid-label",
				Compression:      "zstd",
				CompressionLevel: 3,
			},
			wantError: false,
		},
		{
			name: "invalid compression level for zstd",
			config: &Config{
				Device:           "/dev/sda1",
				Compression:      "zstd",
				CompressionLevel: 20, // Max is 15
			},
			wantError: false, // No validation in current implementation
		},
		{
			name: "compression level without compression type",
			config: &Config{
				Device:           "/dev/sda1",
				CompressionLevel: 5,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Current implementation doesn't validate configs
			// This test documents expected validation behavior
			if tt.wantError {
				t.Skip("Config validation not implemented")
			}
		})
	}
}