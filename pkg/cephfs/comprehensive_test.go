package cephfs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_AllGetterMethods(t *testing.T) {
	t.Run("comprehensive getter method tests", func(t *testing.T) {
		config := &Config{
			ObjectStore:     "filestore",
			OSDMemoryTarget: "8G",
			MONCount:        5,
			MGRCount:        3,
		}

		assert.Equal(t, "filestore", config.GetObjectStore())
		assert.Equal(t, "8G", config.GetOSDMemoryTarget())
		assert.Equal(t, 5, config.GetMONCount())
		assert.Equal(t, 3, config.GetMGRCount())
	})

	t.Run("getter methods with zero values", func(t *testing.T) {
		config := &Config{}

		assert.Equal(t, DefaultObjectStore, config.GetObjectStore())
		assert.Equal(t, DefaultOSDMemoryTarget, config.GetOSDMemoryTarget())
		assert.Equal(t, DefaultMONCount, config.GetMONCount())
		assert.Equal(t, DefaultMGRCount, config.GetMGRCount())
	})

	t.Run("getter methods with empty strings", func(t *testing.T) {
		config := &Config{
			ObjectStore:     "",
			OSDMemoryTarget: "",
			MONCount:        0,
			MGRCount:        0,
		}

		assert.Equal(t, DefaultObjectStore, config.GetObjectStore())
		assert.Equal(t, DefaultOSDMemoryTarget, config.GetOSDMemoryTarget())
		assert.Equal(t, DefaultMONCount, config.GetMONCount())
		assert.Equal(t, DefaultMGRCount, config.GetMGRCount())
	})
}

func TestIsValidCephImage_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		// Valid images
		{"valid quay.io image", "quay.io/ceph/ceph:v18.2.1", true},
		{"valid docker.io image", "docker.io/ceph/ceph:latest", true},
		{"valid short image", "ceph/ceph:v17.2.0", true},
		{"valid with tag", "quay.io/ceph/ceph:stable", true},
		{"valid with complex tag", "quay.io/ceph/ceph:v18.2.1-20231201", true},

		// Invalid images
		{"empty image", "", false},
		{"image without tag", "quay.io/ceph/ceph", false},
		{"invalid registry", "invalid/registry:tag", false},
		{"wrong repository", "quay.io/wrong/repo:tag", false},
		{"random string", "not-an-image", false},
		{"partial match", "quay.io/ceph", false},
		{"wrong prefix", "registry.io/ceph/ceph:tag", false},

		// Edge cases
		{"just colon", ":", false},
		{"empty after colon", "quay.io/ceph/ceph:", true},        // Current implementation allows this
		{"multiple colons", "quay.io/ceph/ceph:tag:extra", true}, // Current implementation allows this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidCephImage(tt.image)
			assert.Equal(t, tt.expected, result, "Image: %s", tt.image)
		})
	}
}

func TestContainsFunction(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		substr   string
		expected bool
	}{
		// Basic cases
		{"exact match", "hello", "hello", true},
		{"substring at start", "hello world", "hello", true},
		{"substring at end", "hello world", "world", true},
		{"substring in middle", "hello world", "lo wo", true},
		{"not found", "hello", "xyz", false},
		{"empty substring", "hello", "", true},
		{"empty string", "", "hello", false},
		{"both empty", "", "", true},

		// Edge cases
		{"single character", "a", "a", true},
		{"case sensitive", "Hello", "hello", false},
		{"repeated pattern", "abababab", "abab", true},
		{"overlapping", "aaaa", "aaa", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.str, tt.substr)
			assert.Equal(t, tt.expected, result, "contains(%q, %q)", tt.str, tt.substr)
		})
	}
}

func TestIndexOfFunction(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		substr   string
		expected int
	}{
		// Basic cases
		{"exact match", "hello", "hello", 0},
		{"substring at start", "hello world", "hello", 0},
		{"substring at end", "hello world", "world", 6},
		{"substring in middle", "hello world", "lo", 3},
		{"not found", "hello", "xyz", -1},
		{"empty substring", "hello", "", 0},
		{"empty string", "", "hello", -1},
		{"both empty", "", "", 0},

		// Edge cases
		{"single character", "a", "a", 0},
		{"first occurrence", "abababab", "ab", 0},
		{"case sensitive", "Hello", "hello", -1},
		{"overlapping pattern", "aaaa", "aa", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexOf(tt.str, tt.substr)
			assert.Equal(t, tt.expected, result, "indexOf(%q, %q)", tt.str, tt.substr)
		})
	}
}

func TestCephFSGetterFunctions(t *testing.T) {
	t.Run("GetCephMGRPort returns expected port", func(t *testing.T) {
		port := GetCephMGRPort()
		assert.Equal(t, 8263, port)
		assert.Greater(t, port, 0)
		assert.Less(t, port, 65536)
	})


	t.Run("GetTerraformCephConfigPath returns correct path", func(t *testing.T) {
		expected := TerraformCephDir + "/main.tf"
		result := GetTerraformCephConfigPath()
		assert.Equal(t, expected, result)
		assert.True(t, strings.HasSuffix(result, ".tf"))
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 3,
				PGNum:           128,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: &Config{
				Name:            "",
				ReplicationSize: 3,
				PGNum:           128,
			},
			wantErr: true,
			errMsg:  "volume name is required",
		},
		{
			name: "negative replication size",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: -1,
				PGNum:           128,
			},
			wantErr: true,
			errMsg:  "replication size must be between 1 and 10",
		},
		{
			name: "too high replication size",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 11,
				PGNum:           128,
			},
			wantErr: true,
			errMsg:  "replication size must be between 1 and 10",
		},
		{
			name: "negative PG number",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 3,
				PGNum:           -1,
			},
			wantErr: true,
			errMsg:  "PG number must be between 1 and 32768",
		},
		{
			name: "too high PG number",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 3,
				PGNum:           40000,
			},
			wantErr: true,
			errMsg:  "PG number must be between 1 and 32768",
		},
		{
			name: "zero values should pass",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 0,
				PGNum:           0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildMountArgs(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected []string
	}{
		{
			name: "basic config",
			config: &Config{
				MonitorHosts: []string{"mon1:6789", "mon2:6789"},
				Name:         "cephfs",
				MountPoint:   "/mnt/cephfs",
				User:         "admin",
			},
			expected: []string{"-t", "ceph", "mon1:6789,mon2:6789:/cephfs", "/mnt/cephfs", "-o", "name=admin"},
		},
		{
			name: "with secret file",
			config: &Config{
				MonitorHosts: []string{"mon1:6789"},
				Name:         "fs",
				MountPoint:   "/mnt/fs",
				User:         "client.admin",
				SecretFile:   "/etc/ceph/admin.secret",
			},
			expected: []string{"-t", "ceph", "mon1:6789:/fs", "/mnt/fs", "-o", "name=client.admin,secretfile=/etc/ceph/admin.secret"},
		},
		{
			name: "with mount options",
			config: &Config{
				MonitorHosts: []string{"mon1:6789"},
				Name:         "fs",
				MountPoint:   "/mnt/fs",
				User:         "admin",
				MountOptions: []string{"noatime", "_netdev"},
			},
			expected: []string{"-t", "ceph", "mon1:6789:/fs", "/mnt/fs", "-o", "name=admin,noatime,_netdev"},
		},
		{
			name: "empty name",
			config: &Config{
				MonitorHosts: []string{"mon1:6789"},
				Name:         "",
				MountPoint:   "/mnt/cephfs",
				User:         "admin",
			},
			expected: []string{"-t", "ceph", "mon1:6789:/", "/mnt/cephfs", "-o", "name=admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMountArgs(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldPersistMount(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name: "with _netdev option",
			config: &Config{
				MountOptions: []string{"noatime", "_netdev"},
			},
			expected: true,
		},
		{
			name: "with auto option",
			config: &Config{
				MountOptions: []string{"auto", "rw"},
			},
			expected: true,
		},
		{
			name: "without persist options",
			config: &Config{
				MountOptions: []string{"noatime", "rw"},
			},
			expected: false,
		},
		{
			name: "empty options",
			config: &Config{
				MountOptions: []string{},
			},
			expected: false,
		},
		{
			name: "nil options",
			config: &Config{
				MountOptions: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldPersistMount(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStructureTypes(t *testing.T) {
	t.Run("DeploymentStatus structure", func(t *testing.T) {
		now := time.Now()
		status := &DeploymentStatus{
			ClusterExists:   true,
			ClusterHealthy:  true,
			OSDs:            []OSDStatus{{ID: 1, UUID: "test-uuid", Up: true, In: true}},
			MONs:            []DaemonStatus{{Name: "mon.a", Host: "host1", Status: "up"}},
			MGRs:            []DaemonStatus{{Name: "mgr.a", Host: "host1", Status: "active"}},
			CephFSAvailable: true,
			LastChecked:     now,
			Version:         "ceph version 18.2.1",
		}

		assert.True(t, status.ClusterExists)
		assert.True(t, status.ClusterHealthy)
		assert.Len(t, status.OSDs, 1)
		assert.Len(t, status.MONs, 1)
		assert.Len(t, status.MGRs, 1)
		assert.True(t, status.CephFSAvailable)
		assert.Equal(t, now, status.LastChecked)
		assert.Equal(t, "ceph version 18.2.1", status.Version)
	})

	t.Run("OSDStatus structure", func(t *testing.T) {
		osd := OSDStatus{
			ID:     1,
			UUID:   "test-uuid-123",
			Up:     true,
			In:     true,
			Device: "/dev/sda",
			Host:   "host1",
			Weight: 1.0,
			Class:  "hdd",
			State:  "up+in",
		}

		assert.Equal(t, 1, osd.ID)
		assert.Equal(t, "test-uuid-123", osd.UUID)
		assert.True(t, osd.Up)
		assert.True(t, osd.In)
		assert.Equal(t, "/dev/sda", osd.Device)
		assert.Equal(t, "host1", osd.Host)
		assert.Equal(t, 1.0, osd.Weight)
		assert.Equal(t, "hdd", osd.Class)
		assert.Equal(t, "up+in", osd.State)
	})

	t.Run("DaemonStatus structure", func(t *testing.T) {
		now := time.Now()
		daemon := DaemonStatus{
			Name:    "mon.a",
			Host:    "host1",
			Status:  "up",
			Version: "18.2.1",
			Started: now,
		}

		assert.Equal(t, "mon.a", daemon.Name)
		assert.Equal(t, "host1", daemon.Host)
		assert.Equal(t, "up", daemon.Status)
		assert.Equal(t, "18.2.1", daemon.Version)
		assert.Equal(t, now, daemon.Started)
	})

	t.Run("VerificationResult structure", func(t *testing.T) {
		result := &VerificationResult{
			ClusterHealthy: true,
			AllOSDsUp:      true,
			AllMONsUp:      true,
			AllMGRsUp:      true,
			CephFSHealthy:  true,
			Errors:         []string{"error1", "error2"},
			Warnings:       []string{"warning1"},
			CheckDuration:  5 * time.Minute,
		}

		assert.True(t, result.ClusterHealthy)
		assert.True(t, result.AllOSDsUp)
		assert.True(t, result.AllMONsUp)
		assert.True(t, result.AllMGRsUp)
		assert.True(t, result.CephFSHealthy)
		assert.Len(t, result.Errors, 2)
		assert.Len(t, result.Warnings, 1)
		assert.Equal(t, 5*time.Minute, result.CheckDuration)
	})
}

func TestMountOptions(t *testing.T) {
	t.Run("performance mount options", func(t *testing.T) {
		options, exists := MountOptions["performance"]
		assert.True(t, exists)
		assert.Contains(t, options, "noatime")
		assert.Contains(t, options, "nodiratime")
		assert.Contains(t, options, "rsize=130048")
		assert.Contains(t, options, "wsize=130048")
		assert.Contains(t, options, "caps_max=65536")
	})

	t.Run("standard mount options", func(t *testing.T) {
		options, exists := MountOptions["standard"]
		assert.True(t, exists)
		assert.Contains(t, options, "noatime")
		assert.Contains(t, options, "_netdev")
	})

	t.Run("secure mount options", func(t *testing.T) {
		options, exists := MountOptions["secure"]
		assert.True(t, exists)
		assert.Contains(t, options, "noatime")
		assert.Contains(t, options, "_netdev")
		assert.Contains(t, options, "secretfile=/etc/ceph/ceph.client.admin.keyring")
	})

	t.Run("nonexistent option type", func(t *testing.T) {
		_, exists := MountOptions["nonexistent"]
		assert.False(t, exists)
	})
}

func TestJSONSerialization(t *testing.T) {
	t.Run("Config serialization", func(t *testing.T) {
		config := &Config{
			ClusterFSID:    "test-fsid",
			AdminHost:      "admin.example.com",
			PublicNetwork:  "10.0.0.0/24",
			ClusterNetwork: "10.1.0.0/24",
			MONCount:       3,
			MGRCount:       2,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		var unmarshaled Config
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, config.ClusterFSID, unmarshaled.ClusterFSID)
		assert.Equal(t, config.AdminHost, unmarshaled.AdminHost)
		assert.Equal(t, config.PublicNetwork, unmarshaled.PublicNetwork)
		assert.Equal(t, config.ClusterNetwork, unmarshaled.ClusterNetwork)
		assert.Equal(t, config.MONCount, unmarshaled.MONCount)
		assert.Equal(t, config.MGRCount, unmarshaled.MGRCount)
	})

	t.Run("VerificationResult serialization", func(t *testing.T) {
		result := &VerificationResult{
			ClusterHealthy: true,
			AllOSDsUp:      false,
			AllMONsUp:      true,
			AllMGRsUp:      true,
			CephFSHealthy:  false,
			Errors:         []string{"test error"},
			Warnings:       []string{"test warning"},
			CheckDuration:  time.Minute,
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var unmarshaled VerificationResult
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, result.ClusterHealthy, unmarshaled.ClusterHealthy)
		assert.Equal(t, result.AllOSDsUp, unmarshaled.AllOSDsUp)
		assert.Equal(t, result.AllMONsUp, unmarshaled.AllMONsUp)
		assert.Equal(t, result.AllMGRsUp, unmarshaled.AllMGRsUp)
		assert.Equal(t, result.CephFSHealthy, unmarshaled.CephFSHealthy)
		assert.Equal(t, result.Errors, unmarshaled.Errors)
		assert.Equal(t, result.Warnings, unmarshaled.Warnings)
		assert.Equal(t, result.CheckDuration, unmarshaled.CheckDuration)
	})
}

func TestConstants(t *testing.T) {
	t.Run("verify important constants", func(t *testing.T) {
		assert.Equal(t, "quay.io/ceph/ceph:v18.2.1", DefaultCephImage)
		assert.Equal(t, "v18.2.1", DefaultCephVersion)
		assert.Equal(t, "/etc/ceph", CephConfigDir)
		assert.Equal(t, "/var/lib/ceph", CephDataDir)
		assert.Equal(t, "/var/log/ceph", CephLogDir)
		assert.Equal(t, "bluestore", DefaultObjectStore)
		assert.Equal(t, "4G", DefaultOSDMemoryTarget)
		assert.Equal(t, 3, DefaultMONCount)
		assert.Equal(t, 2, DefaultMGRCount)
		assert.Equal(t, "root", DefaultSSHUser)
		assert.Equal(t, 6789, CephMONPort)
		assert.Equal(t, 6800, CephOSDPort)
		assert.Equal(t, 6810, CephFSPort)
	})

	t.Run("verify default values", func(t *testing.T) {
		assert.Equal(t, 3, DefaultReplicationSize)
		assert.Equal(t, 128, DefaultPGNum)
		assert.Equal(t, "4096M", DefaultCacheSize)
		assert.Equal(t, 8192, DefaultReadAheadKB)
		assert.Equal(t, 4096, MinimumOSDMemoryMB)
		assert.Equal(t, 10, MinimumDiskSpaceGB)
	})

	t.Run("verify test constants", func(t *testing.T) {
		assert.Equal(t, "/mnt/cephfs-test", TestMountPoint)
		assert.Equal(t, "eos-cephfs-test.txt", TestFileName)
		assert.Equal(t, "EOS CephFS deployment verification test", TestFileContent)
	})
}

func TestVolumeInfo(t *testing.T) {
	t.Run("VolumeInfo structure", func(t *testing.T) {
		now := time.Now()
		volume := VolumeInfo{
			Name:          "test-volume",
			ID:            "vol-123",
			State:         "active",
			CreatedAt:     now,
			Size:          1000000000, // 1GB
			UsedSize:      500000000,  // 500MB
			AvailableSize: 500000000,  // 500MB
			MountPoints:   []string{"/mnt/volume1", "/mnt/volume2"},
			DataPools:     []string{"data-pool"},
			MetadataPools: []string{"metadata-pool"},
		}

		assert.Equal(t, "test-volume", volume.Name)
		assert.Equal(t, "vol-123", volume.ID)
		assert.Equal(t, "active", volume.State)
		assert.Equal(t, now, volume.CreatedAt)
		assert.Equal(t, int64(1000000000), volume.Size)
		assert.Equal(t, int64(500000000), volume.UsedSize)
		assert.Equal(t, int64(500000000), volume.AvailableSize)
		assert.Len(t, volume.MountPoints, 2)
		assert.Len(t, volume.DataPools, 1)
		assert.Len(t, volume.MetadataPools, 1)
	})
}

func TestFileOperations(t *testing.T) {
	t.Run("createTempCephFile helper", func(t *testing.T) {
		content := "test ceph file content"

		filePath, err := createTempCephFile(content)
		require.NoError(t, err)
		defer removeTempCephFile(filePath)

		// Verify file exists
		_, err = os.Stat(filePath)
		assert.NoError(t, err)

		// Verify content
		readContent, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, content, string(readContent))

		// Verify filename pattern
		assert.True(t, strings.Contains(filepath.Base(filePath), "ceph-fuzz-test-"))
	})

	t.Run("removeTempCephFile helper", func(t *testing.T) {
		filePath, err := createTempCephFile("test")
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(filePath)
		assert.NoError(t, err)

		// Remove file
		removeTempCephFile(filePath)

		// Verify file is gone
		_, err = os.Stat(filePath)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestCephServiceSpec(t *testing.T) {
	t.Run("CephServiceSpec structure", func(t *testing.T) {
		spec := CephServiceSpec{
			ServiceType: "osd",
			ServiceID:   "all-available-devices",
			Placement: CephPlacementSpec{
				HostPattern: "osd-*",
				Hosts:       []string{"host1", "host2", "host3"},
				Count:       3,
			},
			Spec: map[string]any{
				"data_devices": map[string]any{
					"all": true,
				},
				"filter_logic": "AND",
				"objectstore":  "bluestore",
			},
		}

		assert.Equal(t, "osd", spec.ServiceType)
		assert.Equal(t, "all-available-devices", spec.ServiceID)
		assert.Equal(t, "osd-*", spec.Placement.HostPattern)
		assert.Len(t, spec.Placement.Hosts, 3)
		assert.Equal(t, 3, spec.Placement.Count)
		assert.NotNil(t, spec.Spec)
		assert.Equal(t, "bluestore", spec.Spec["objectstore"])
	})

	t.Run("CephOSDSpec structure", func(t *testing.T) {
		rotational := false
		osdSpec := CephOSDSpec{
			DataDevices: CephDeviceSpec{
				All:        true,
				Paths:      []string{"/dev/sda", "/dev/sdb"},
				Rotational: &rotational,
			},
			FilterLogic: "AND",
			ObjectStore: "bluestore",
			Rotational:  &rotational,
			Paths:       []string{"/dev/sdc"},
		}

		assert.True(t, osdSpec.DataDevices.All)
		assert.Len(t, osdSpec.DataDevices.Paths, 2)
		assert.NotNil(t, osdSpec.DataDevices.Rotational)
		assert.False(t, *osdSpec.DataDevices.Rotational)
		assert.Equal(t, "AND", osdSpec.FilterLogic)
		assert.Equal(t, "bluestore", osdSpec.ObjectStore)
		assert.NotNil(t, osdSpec.Rotational)
		assert.False(t, *osdSpec.Rotational)
		assert.Len(t, osdSpec.Paths, 1)
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("validateConfig error handling", func(t *testing.T) {
		// Test multiple error conditions
		invalidConfigs := []*Config{
			{Name: "", ReplicationSize: 3, PGNum: 128},       // Empty name
			{Name: "test", ReplicationSize: -1, PGNum: 128},  // Invalid replication
			{Name: "test", ReplicationSize: 11, PGNum: 128},  // Invalid replication
			{Name: "test", ReplicationSize: 3, PGNum: -1},    // Invalid PG num
			{Name: "test", ReplicationSize: 3, PGNum: 50000}, // Invalid PG num
		}

		for i, config := range invalidConfigs {
			err := validateConfig(config)
			assert.Error(t, err, "Config %d should be invalid", i)
		}
	})

	t.Run("helper function edge cases", func(t *testing.T) {
		// Test edge cases that might cause issues
		testCases := []struct {
			str    string
			substr string
		}{
			{"", ""},
			{"a", ""},
			{"", "a"},
			{"very long string with lots of content", "content"},
			{"short", "very long substring that is longer than the string"},
		}

		for _, tc := range testCases {
			// These should not panic
			_ = contains(tc.str, tc.substr)
			_ = indexOf(tc.str, tc.substr)
		}
	})
}
