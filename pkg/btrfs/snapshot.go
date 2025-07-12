package btrfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateSnapshot creates a BTRFS snapshot
func CreateSnapshot(rc *eos_io.RuntimeContext, config *SnapshotConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate snapshot configuration for security
	if err := validateSnapshotConfig(config); err != nil {
		return err
	}

	// ASSESS
	logger.Info("Assessing snapshot creation requirements",
		zap.String("source", config.SourcePath),
		zap.String("destination", config.SnapshotPath))

	// Check if source exists and is a subvolume
	if !isSubvolume(rc, config.SourcePath) {
		return eos_err.NewUserError("source path %s is not a BTRFS subvolume", config.SourcePath)
	}

	// Check if destination already exists
	if _, err := os.Stat(config.SnapshotPath); err == nil {
		return eos_err.NewUserError("snapshot destination already exists: %s", config.SnapshotPath)
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(config.SnapshotPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// INTERVENE
	logger.Info("Creating BTRFS snapshot",
		zap.Bool("readonly", config.Readonly))

	// Build snapshot command
	args := []string{"subvolume", "snapshot"}

	if config.Readonly {
		args = append(args, "-r")
	}

	args = append(args, config.SourcePath, config.SnapshotPath)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "btrfs",
		Args:    args,
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w, output: %s", err, output)
	}

	logger.Debug("Snapshot created",
		zap.String("output", output))

	// EVALUATE
	logger.Info("Verifying snapshot creation")

	// Verify snapshot exists and is valid
	if !isSubvolume(rc, config.SnapshotPath) {
		return fmt.Errorf("snapshot verification failed: %s is not a valid subvolume",
			config.SnapshotPath)
	}

	// Get snapshot info
	info, err := GetSubvolumeInfo(rc, config.SnapshotPath)
	if err != nil {
		logger.Warn("Failed to get snapshot info",
			zap.Error(err))
	} else {
		logger.Info("Snapshot created successfully",
			zap.String("path", config.SnapshotPath),
			zap.Int64("id", info.ID),
			zap.String("uuid", info.UUID))
	}

	return nil
}

// ListSnapshots lists all snapshots of a subvolume
func ListSnapshots(rc *eos_io.RuntimeContext, sourcePath string) ([]*SubvolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate source path for security
	if err := validateSubvolumePath(sourcePath); err != nil {
		return nil, fmt.Errorf("invalid source path: %w", err)
	}

	// ASSESS
	logger.Info("Assessing subvolume for snapshot listing",
		zap.String("source", sourcePath))

	// Get source subvolume info
	sourceInfo, err := GetSubvolumeInfo(rc, sourcePath)
	if err != nil {
		return nil, eos_err.NewUserError("failed to get source subvolume info: %w", err)
	}

	// INTERVENE
	logger.Info("Listing snapshots",
		zap.String("sourceUUID", sourceInfo.UUID))

	// Find the root mount point
	rootMount := findBTRFSRoot(rc, sourcePath)
	if rootMount == "" {
		return nil, fmt.Errorf("failed to find BTRFS root mount")
	}

	// List all subvolumes
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "btrfs",
		Args:    []string{"subvolume", "list", "-u", "-q", rootMount},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list subvolumes: %w", err)
	}

	snapshots := make([]*SubvolumeInfo, 0)

	// Parse output and find snapshots
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse subvolume info
		info := parseSubvolumeListLine(line)
		if info == nil {
			continue
		}

		// Check if this is a snapshot of our source
		if info.ParentUUID == sourceInfo.UUID {
			// Get full path
			fullPath := filepath.Join(rootMount, info.Path)

			// Get detailed info
			if detailedInfo, err := GetSubvolumeInfo(rc, fullPath); err == nil {
				snapshots = append(snapshots, detailedInfo)
			} else {
				snapshots = append(snapshots, info)
			}
		}
	}

	// EVALUATE
	logger.Info("Snapshot listing completed",
		zap.Int("count", len(snapshots)))

	return snapshots, nil
}

// DeleteSnapshot deletes a BTRFS snapshot
func DeleteSnapshot(rc *eos_io.RuntimeContext, snapshotPath string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate snapshot path for security
	if err := validateSubvolumePath(snapshotPath); err != nil {
		return fmt.Errorf("invalid snapshot path: %w", err)
	}

	// ASSESS
	logger.Info("Assessing snapshot for deletion",
		zap.String("path", snapshotPath))

	// Check if path is a subvolume
	if !isSubvolume(rc, snapshotPath) {
		return eos_err.NewUserError("path %s is not a BTRFS subvolume", snapshotPath)
	}

	// Get snapshot info
	info, err := GetSubvolumeInfo(rc, snapshotPath)
	if err != nil {
		return fmt.Errorf("failed to get snapshot info: %w", err)
	}

	// Check if it has snapshots (nested snapshots)
	if len(info.Snapshots) > 0 && !force {
		return eos_err.NewUserError("snapshot has %d nested snapshots. Use --force to delete anyway",
			len(info.Snapshots))
	}

	// INTERVENE
	logger.Info("Deleting snapshot",
		zap.String("path", snapshotPath),
		zap.Bool("force", force))

	// Delete the snapshot
	args := []string{"subvolume", "delete"}

	if force {
		// Add commit flag for immediate deletion
		args = append(args, "--commit-after")
	}

	args = append(args, snapshotPath)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "btrfs",
		Args:    args,
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to delete snapshot: %w, output: %s", err, output)
	}

	// EVALUATE
	logger.Info("Verifying snapshot deletion")

	// Verify snapshot was deleted
	if _, err := os.Stat(snapshotPath); err == nil {
		return fmt.Errorf("snapshot deletion verification failed: path still exists")
	}

	logger.Info("Snapshot deleted successfully",
		zap.String("path", snapshotPath))

	return nil
}

// RotateSnapshots implements snapshot rotation policy
func RotateSnapshots(rc *eos_io.RuntimeContext, sourcePath string, maxSnapshots int, maxAge time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate source path for security
	if err := validateSubvolumePath(sourcePath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}

	// ASSESS
	logger.Info("Assessing snapshots for rotation",
		zap.String("source", sourcePath),
		zap.Int("maxSnapshots", maxSnapshots),
		zap.Duration("maxAge", maxAge))

	// List all snapshots
	snapshots, err := ListSnapshots(rc, sourcePath)
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %w", err)
	}

	if len(snapshots) == 0 {
		logger.Info("No snapshots found to rotate")
		return nil
	}

	// INTERVENE
	logger.Info("Rotating snapshots",
		zap.Int("currentCount", len(snapshots)))

	toDelete := make([]*SubvolumeInfo, 0)
	now := time.Now()

	// Sort snapshots by creation time (newest first)
	sortSnapshotsByTime(snapshots)

	// Apply rotation policies
	for i, snap := range snapshots {
		deleteSnapshot := false

		// Check count policy
		if maxSnapshots > 0 && i >= maxSnapshots {
			deleteSnapshot = true
			logger.Debug("Snapshot exceeds count limit",
				zap.String("path", snap.Path),
				zap.Int("position", i+1),
				zap.Int("maxSnapshots", maxSnapshots))
		}

		// Check age policy
		if maxAge > 0 && snap.SendTime.Before(now.Add(-maxAge)) {
			deleteSnapshot = true
			logger.Debug("Snapshot exceeds age limit",
				zap.String("path", snap.Path),
				zap.Time("created", snap.SendTime),
				zap.Duration("age", now.Sub(snap.SendTime)))
		}

		if deleteSnapshot {
			toDelete = append(toDelete, snap)
		}
	}

	// Delete old snapshots
	deletedCount := 0
	for _, snap := range toDelete {
		if err := DeleteSnapshot(rc, snap.Path, true); err != nil {
			logger.Warn("Failed to delete snapshot during rotation",
				zap.String("path", snap.Path),
				zap.Error(err))
		} else {
			deletedCount++
		}
	}

	// EVALUATE
	logger.Info("Snapshot rotation completed",
		zap.Int("deleted", deletedCount),
		zap.Int("remaining", len(snapshots)-deletedCount))

	return nil
}

// Helper functions

func isSubvolume(rc *eos_io.RuntimeContext, path string) bool {
	// Check if path is a BTRFS subvolume
	err := execute.RunSimple(rc.Ctx, "btrfs", "subvolume", "show", path)
	return err == nil
}

func findBTRFSRoot(rc *eos_io.RuntimeContext, path string) string {
	// Find the root mount point of the BTRFS filesystem
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "findmnt",
		Args:    []string{"-n", "-o", "TARGET", "-T", path, "-t", "btrfs"},
		Capture: true,
	})
	if err == nil {
		return strings.TrimSpace(output)
	}
	return ""
}

func parseSubvolumeListLine(line string) *SubvolumeInfo {
	// Parse output from btrfs subvolume list
	// Example: ID 257 gen 10 parent 5 top level 5 parent_uuid - uuid 12345 path subvol1

	info := &SubvolumeInfo{}
	parts := strings.Fields(line)

	for i := 0; i < len(parts)-1; i++ {
		switch parts[i] {
		case "ID":
			fmt.Sscanf(parts[i+1], "%d", &info.ID)
		case "parent":
			fmt.Sscanf(parts[i+1], "%d", &info.ParentID)
		case "top":
			if i+2 < len(parts) && parts[i+1] == "level" {
				fmt.Sscanf(parts[i+2], "%d", &info.TopLevel)
			}
		case "parent_uuid":
			if parts[i+1] != "-" {
				info.ParentUUID = parts[i+1]
			}
		case "uuid":
			info.UUID = parts[i+1]
		case "path":
			// Path is everything after "path"
			info.Path = strings.Join(parts[i+1:], " ")
			return info
		}
	}

	return info
}

func sortSnapshotsByTime(snapshots []*SubvolumeInfo) {
	// Simple bubble sort by send time (newest first)
	for i := 0; i < len(snapshots)-1; i++ {
		for j := 0; j < len(snapshots)-i-1; j++ {
			if snapshots[j].SendTime.Before(snapshots[j+1].SendTime) {
				snapshots[j], snapshots[j+1] = snapshots[j+1], snapshots[j]
			}
		}
	}
}

// validateSnapshotConfig validates snapshot configuration for security vulnerabilities
func validateSnapshotConfig(config *SnapshotConfig) error {
	// Validate source path
	if err := validateSubvolumePath(config.SourcePath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}

	// Validate snapshot path
	if err := validateSubvolumePath(config.SnapshotPath); err != nil {
		return fmt.Errorf("invalid snapshot path: %w", err)
	}

	return nil
}

// Note: validateSubvolumePath function is defined in create.go and reused here
