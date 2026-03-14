// pkg/chats/backup.go
// Business logic for backing up AI chat data using restic.
//
// RATIONALE: Follows Assess -> Intervene -> Evaluate pattern.
// Uses existing backup.Client infrastructure for restic operations.

package chats

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupConfig holds configuration for a chat backup operation
type BackupConfig struct {
	// RepoName is the restic repository name to use
	RepoName string

	// User is the target user (empty = auto-detect via SUDO_USER)
	User string

	// Tools limits backup to specific tool names (empty = all found)
	Tools []string

	// DryRun shows what would be backed up without creating backup
	DryRun bool
}

// BackupResult holds the result of a chat backup operation
type BackupResult struct {
	// ToolsBacked is the list of tools that were backed up
	ToolsBacked []string

	// Paths is the list of paths included in the backup
	Paths []string

	// Output is the raw restic output
	Output string

	// Duration is how long the backup took
	Duration time.Duration
}

// RunBackup discovers AI chat data and backs it up to restic.
// Follows Assess -> Intervene -> Evaluate.
func RunBackup(rc *eos_io.RuntimeContext, config *BackupConfig) (*BackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// === ASSESS ===
	discovery, err := DiscoverChatData(rc, config.User)
	if err != nil {
		return nil, fmt.Errorf("discovering chat data: %w", err)
	}

	tools := FilterByTools(discovery, config.Tools)
	if len(tools) == 0 {
		return nil, fmt.Errorf("no AI chat data found for user %q\n"+
			"Checked paths in: %s\n"+
			"Supported tools: %s",
			discovery.User, discovery.HomeDir,
			strings.Join(AvailableToolNames(), ", "))
	}

	// Collect paths and excludes
	var paths []string
	var excludes []string
	var toolNames []string

	for _, tool := range tools {
		paths = append(paths, tool.DataPath)
		toolNames = append(toolNames, tool.DisplayName)

		// Convert relative excludes to absolute paths
		for _, exc := range tool.Excludes {
			excludes = append(excludes, filepath.Join(discovery.HomeDir, exc))
		}
	}

	logger.Info("Chat backup plan",
		zap.Strings("tools", toolNames),
		zap.Strings("paths", paths),
		zap.Int("exclude_count", len(excludes)),
		zap.Bool("dry_run", config.DryRun))

	// === INTERVENE ===
	client, err := backup.NewClient(rc, config.RepoName)
	if err != nil {
		return nil, fmt.Errorf("creating backup client: %w", err)
	}

	// Build restic backup args
	args := []string{"backup"}
	args = append(args, paths...)

	for _, exc := range excludes {
		args = append(args, "--exclude", exc)
	}

	// Tag with metadata for easy filtering/restore
	args = append(args, "--tag", BackupTagPrefix)
	args = append(args, "--tag", fmt.Sprintf("user:%s", discovery.User))
	for _, tool := range tools {
		args = append(args, "--tag", fmt.Sprintf("%s:%s", BackupTagTool, tool.Name))
	}

	if config.DryRun {
		args = append(args, "--dry-run")
	}

	start := time.Now()
	output, err := client.RunRestic(args...)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("restic backup failed: %w", err)
	}

	// === EVALUATE ===
	result := &BackupResult{
		ToolsBacked: toolNames,
		Paths:       paths,
		Output:      string(output),
		Duration:    duration,
	}

	logger.Info("Chat backup complete",
		zap.Strings("tools", toolNames),
		zap.Duration("duration", duration),
		zap.Bool("dry_run", config.DryRun))

	return result, nil
}
