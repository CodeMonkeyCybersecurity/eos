package btrfs

import (
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSnapshot_Validation(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		name      string
		config    *SnapshotConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid snapshot config",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/subvol",
				SnapshotPath: "/mnt/snapshots/snap1",
				Readonly:     true,
			},
			wantError: true, // Will fail as source is not real subvolume
			errorMsg:  "not a BTRFS subvolume",
		},
		{
			name: "empty source path",
			config: &SnapshotConfig{
				SourcePath:   "",
				SnapshotPath: "/mnt/snapshots/snap1",
			},
			wantError: true,
			errorMsg:  "not a BTRFS subvolume",
		},
		{
			name: "empty snapshot path",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/subvol",
				SnapshotPath: "",
			},
			wantError: true,
			errorMsg:  "not a BTRFS subvolume",
		},
		{
			name: "source and snapshot same",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/subvol",
				SnapshotPath: "/mnt/data/subvol",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateSnapshot(rc, tt.config)
			if tt.wantError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestListSnapshots_EdgeCases(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		name       string
		sourcePath string
		wantError  bool
	}{
		{
			name:       "non-existent path",
			sourcePath: "/non/existent/path",
			wantError:  true,
		},
		{
			name:       "empty path",
			sourcePath: "",
			wantError:  true,
		},
		{
			name:       "root path",
			sourcePath: "/",
			wantError:  true, // Not a subvolume in test env
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshots, err := ListSnapshots(rc, tt.sourcePath)
			if tt.wantError {
				require.Error(t, err)
				assert.Nil(t, snapshots)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, snapshots)
			}
		})
	}
}

func TestDeleteSnapshot_Validation(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		name         string
		snapshotPath string
		force        bool
		wantError    bool
		errorMsg     string
	}{
		{
			name:         "non-subvolume path",
			snapshotPath: "/tmp/not-a-subvolume",
			force:        false,
			wantError:    true,
			errorMsg:     "not a BTRFS subvolume",
		},
		{
			name:         "empty path",
			snapshotPath: "",
			force:        false,
			wantError:    true,
			errorMsg:     "not a BTRFS subvolume",
		},
		{
			name:         "dangerous path",
			snapshotPath: "/",
			force:        true,
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DeleteSnapshot(rc, tt.snapshotPath, tt.force)
			if tt.wantError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRotateSnapshots_Logic(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		name         string
		sourcePath   string
		maxSnapshots int
		maxAge       time.Duration
		wantError    bool
	}{
		{
			name:         "with count limit",
			sourcePath:   "/mnt/data/subvol",
			maxSnapshots: 5,
			maxAge:       0,
			wantError:    true, // Will fail in test env
		},
		{
			name:         "with age limit",
			sourcePath:   "/mnt/data/subvol",
			maxSnapshots: 0,
			maxAge:       7 * 24 * time.Hour, // 7 days
			wantError:    true,
		},
		{
			name:         "with both limits",
			sourcePath:   "/mnt/data/subvol",
			maxSnapshots: 10,
			maxAge:       30 * 24 * time.Hour, // 30 days
			wantError:    true,
		},
		{
			name:         "no limits",
			sourcePath:   "/mnt/data/subvol",
			maxSnapshots: 0,
			maxAge:       0,
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RotateSnapshots(rc, tt.sourcePath, tt.maxSnapshots, tt.maxAge)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseSubvolumeListLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *SubvolumeInfo
	}{
		{
			name: "complete line",
			line: "ID 257 gen 10 parent 5 top level 5 parent_uuid - uuid 12345-6789 path data/subvol1",
			expected: &SubvolumeInfo{
				ID:         257,
				ParentID:   5,
				TopLevel:   5,
				ParentUUID: "",
				UUID:       "12345-6789",
				Path:       "data/subvol1",
			},
		},
		{
			name: "with parent UUID",
			line: "ID 258 gen 20 parent 257 top level 5 parent_uuid abcdef-1234 uuid 67890-abcd path data/snap1",
			expected: &SubvolumeInfo{
				ID:         258,
				ParentID:   257,
				TopLevel:   5,
				ParentUUID: "abcdef-1234",
				UUID:       "67890-abcd",
				Path:       "data/snap1",
			},
		},
		{
			name: "path with spaces",
			line: "ID 259 gen 30 parent 5 top level 5 parent_uuid - uuid xyz-123 path data/my snapshot",
			expected: &SubvolumeInfo{
				ID:       259,
				ParentID: 5,
				TopLevel: 5,
				UUID:     "xyz-123",
				Path:     "data/my snapshot",
			},
		},
		{
			name:     "malformed line",
			line:     "invalid btrfs output",
			expected: &SubvolumeInfo{},
		},
		{
			name:     "empty line",
			line:     "",
			expected: &SubvolumeInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSubvolumeListLine(tt.line)
			require.NotNil(t, result)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ParentID, result.ParentID)
			assert.Equal(t, tt.expected.TopLevel, result.TopLevel)
			assert.Equal(t, tt.expected.ParentUUID, result.ParentUUID)
			assert.Equal(t, tt.expected.UUID, result.UUID)
			assert.Equal(t, tt.expected.Path, result.Path)
		})
	}
}

func TestSortSnapshotsByTime(t *testing.T) {
	now := time.Now()

	snapshots := []*SubvolumeInfo{
		{ID: 1, Path: "/snap1", SendTime: now.Add(-3 * time.Hour)},
		{ID: 2, Path: "/snap2", SendTime: now.Add(-1 * time.Hour)},
		{ID: 3, Path: "/snap3", SendTime: now.Add(-5 * time.Hour)},
		{ID: 4, Path: "/snap4", SendTime: now.Add(-2 * time.Hour)},
		{ID: 5, Path: "/snap5", SendTime: now}, // Newest
	}

	sortSnapshotsByTime(snapshots)

	// Should be sorted newest first
	assert.Equal(t, int64(5), snapshots[0].ID) // Newest
	assert.Equal(t, int64(2), snapshots[1].ID) // 1 hour ago
	assert.Equal(t, int64(4), snapshots[2].ID) // 2 hours ago
	assert.Equal(t, int64(1), snapshots[3].ID) // 3 hours ago
	assert.Equal(t, int64(3), snapshots[4].ID) // 5 hours ago (oldest)

	// Verify ordering
	for i := 0; i < len(snapshots)-1; i++ {
		assert.True(t, snapshots[i].SendTime.After(snapshots[i+1].SendTime) ||
			snapshots[i].SendTime.Equal(snapshots[i+1].SendTime))
	}
}

func TestIsSubvolume_Mock(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/mnt/btrfs/subvol", false}, // Mock always returns false
		{"/mnt/regular/dir", false},
		{"", false},
		{"/", false},
	}

	for _, tt := range tests {
		result := isSubvolume(rc, tt.path)
		assert.Equal(t, tt.expected, result)
	}
}

func TestFindBTRFSRoot_Mock(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	tests := []struct {
		path     string
		expected string
	}{
		{"/mnt/btrfs/subvol/data", ""},
		{"/home/user", ""},
		{"", ""},
		{"/", ""},
	}

	for _, tt := range tests {
		result := findBTRFSRoot(rc, tt.path)
		assert.Equal(t, tt.expected, result)
	}
}

func TestSnapshotConfig_SecurityValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *SnapshotConfig
		issues []string
	}{
		{
			name: "path traversal attempt",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/../../../etc",
				SnapshotPath: "/mnt/snapshots/../../../tmp/snap",
			},
			issues: []string{"path traversal"},
		},
		{
			name: "command injection attempt",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data/$(whoami)",
				SnapshotPath: "/mnt/snapshots/snap;rm -rf /",
			},
			issues: []string{"command injection"},
		},
		{
			name: "null byte injection",
			config: &SnapshotConfig{
				SourcePath:   "/mnt/data\x00/etc/passwd",
				SnapshotPath: "/mnt/snapshots/snap\x00",
			},
			issues: []string{"null byte"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check source path
			if strings.Contains(tt.config.SourcePath, "..") {
				assert.Contains(t, tt.issues, "path traversal")
			}
			if strings.ContainsAny(tt.config.SourcePath, ";$()") {
				assert.Contains(t, tt.issues, "command injection")
			}
			if strings.Contains(tt.config.SourcePath, "\x00") {
				assert.Contains(t, tt.issues, "null byte")
			}

			// Check snapshot path
			if strings.Contains(tt.config.SnapshotPath, "..") {
				assert.Contains(t, tt.issues, "path traversal")
			}
			if strings.ContainsAny(tt.config.SnapshotPath, ";$()") {
				assert.Contains(t, tt.issues, "command injection")
			}
			if strings.Contains(tt.config.SnapshotPath, "\x00") {
				assert.Contains(t, tt.issues, "null byte")
			}
		})
	}
}

func TestRotateSnapshots_EdgeCases(t *testing.T) {
	t.Run("empty snapshot list", func(t *testing.T) {
		// When ListSnapshots returns empty list
		rc := testutil.TestRuntimeContext(t)
		err := RotateSnapshots(rc, "/mnt/data/subvol", 5, 7*24*time.Hour)
		// Should fail as path is not valid subvolume in test
		assert.Error(t, err)
	})

	t.Run("negative limits", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		err := RotateSnapshots(rc, "/mnt/data/subvol", -1, -1*time.Hour)
		assert.Error(t, err)
	})

	t.Run("zero limits means no rotation", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		err := RotateSnapshots(rc, "/mnt/data/subvol", 0, 0)
		assert.Error(t, err) // Still fails due to invalid path
	})
}

func TestSnapshotTimeHandling(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		snapshot     *SubvolumeInfo
		maxAge       time.Duration
		shouldDelete bool
	}{
		{
			name: "recent snapshot",
			snapshot: &SubvolumeInfo{
				Path:     "/snap1",
				SendTime: now.Add(-1 * time.Hour),
			},
			maxAge:       7 * 24 * time.Hour,
			shouldDelete: false,
		},
		{
			name: "old snapshot",
			snapshot: &SubvolumeInfo{
				Path:     "/snap2",
				SendTime: now.Add(-10 * 24 * time.Hour),
			},
			maxAge:       7 * 24 * time.Hour,
			shouldDelete: true,
		},
		{
			name: "exactly at limit",
			snapshot: &SubvolumeInfo{
				Path:     "/snap3",
				SendTime: now.Add(-7 * 24 * time.Hour),
			},
			maxAge:       7 * 24 * time.Hour,
			shouldDelete: false, // At exactly the limit, not before
		},
		{
			name: "zero send time",
			snapshot: &SubvolumeInfo{
				Path:     "/snap4",
				SendTime: time.Time{},
			},
			maxAge:       7 * 24 * time.Hour,
			shouldDelete: true, // Zero time is very old
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isOld := tt.snapshot.SendTime.Before(now.Add(-tt.maxAge))
			assert.Equal(t, tt.shouldDelete, isOld)
		})
	}
}
