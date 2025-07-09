package docker_volume

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PruneVolumes removes unused Docker volumes
func PruneVolumes(rc *eos_io.RuntimeContext, config *PruneConfig) (int64, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volumes for pruning",
		zap.Bool("all", config.All),
		zap.Bool("dryRun", config.DryRun))

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return 0, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// Build filters
	pruneFilters := filters.NewArgs()
	for _, filter := range config.Filter {
		parts := strings.SplitN(filter, "=", 2)
		if len(parts) == 2 {
			pruneFilters.Add(parts[0], parts[1])
		}
	}

	// List volumes to be pruned
	volumesToPrune, err := getVolumesToPrune(rc, cli, config)
	if err != nil {
		return 0, fmt.Errorf("failed to identify volumes to prune: %w", err)
	}

	if len(volumesToPrune) == 0 {
		logger.Info("No volumes to prune")
		return 0, nil
	}

	// INTERVENE
	logger.Info("Pruning Docker volumes",
		zap.Int("count", len(volumesToPrune)))

	var totalReclaimed int64

	if config.DryRun {
		// Calculate space that would be reclaimed
		for _, vol := range volumesToPrune {
			if vol.UsageData != nil {
				totalReclaimed += vol.UsageData.Size
			}
			logger.Info("Would remove volume",
				zap.String("name", vol.Name),
				zap.String("driver", vol.Driver))
		}
	} else {
		// Actually prune volumes
		report, err := cli.VolumesPrune(rc.Ctx, pruneFilters)
		if err != nil {
			return 0, fmt.Errorf("failed to prune volumes: %w", err)
		}

		totalReclaimed = int64(report.SpaceReclaimed)

		logger.Debug("Volumes pruned",
			zap.Strings("removed", report.VolumesDeleted))
	}

	// EVALUATE
	logger.Info("Volume pruning completed",
		zap.Int64("spaceReclaimed", totalReclaimed),
		zap.String("spaceReclaimedHuman", formatBytes(totalReclaimed)))

	return totalReclaimed, nil
}

// PruneUnusedVolumes removes volumes not used by any container
func PruneUnusedVolumes(rc *eos_io.RuntimeContext, keepDays int) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing unused volumes for pruning",
		zap.Int("keepDays", keepDays))

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// List all volumes
	volumes, err := cli.VolumeList(rc.Ctx, volume.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list volumes: %w", err)
	}

	// INTERVENE
	cutoffTime := time.Now().AddDate(0, 0, -keepDays)
	removedCount := 0
	var totalReclaimed int64

	for _, vol := range volumes.Volumes {
		// Skip volumes in use
		if vol.UsageData != nil && vol.UsageData.RefCount > 0 {
			continue
		}

		// Parse creation time
		createdAt, err := time.Parse(time.RFC3339, vol.CreatedAt)
		if err != nil {
			logger.Warn("Failed to parse volume creation time",
				zap.String("volume", vol.Name),
				zap.Error(err))
			continue
		}

		// Check if volume is old enough
		if createdAt.Before(cutoffTime) {
			logger.Info("Removing unused volume",
				zap.String("name", vol.Name),
				zap.Time("created", createdAt))

			if err := cli.VolumeRemove(rc.Ctx, vol.Name, false); err != nil {
				logger.Warn("Failed to remove volume",
					zap.String("name", vol.Name),
					zap.Error(err))
			} else {
				removedCount++
				if vol.UsageData != nil {
					totalReclaimed += vol.UsageData.Size
				}
			}
		}
	}

	// EVALUATE
	logger.Info("Unused volume pruning completed",
		zap.Int("removed", removedCount),
		zap.Int64("spaceReclaimed", totalReclaimed))

	return nil
}

// PruneVolumesBySize removes volumes exceeding size threshold
func PruneVolumesBySize(rc *eos_io.RuntimeContext, maxSize string, excludePatterns []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing volumes by size for pruning",
		zap.String("maxSize", maxSize))

	// Parse max size
	maxSizeBytes, err := parseSize(maxSize)
	if err != nil {
		return eos_err.NewUserError("invalid size format: %s", maxSize)
	}

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// INTERVENE
	// Get volume sizes
	volumes, err := cli.VolumeList(rc.Ctx, volume.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list volumes: %w", err)
	}

	removedCount := 0
	var totalReclaimed int64

	for _, vol := range volumes.Volumes {
		// Skip if no usage data
		if vol.UsageData == nil {
			continue
		}

		// Skip excluded volumes
		if isExcluded(vol.Name, excludePatterns) {
			logger.Debug("Skipping excluded volume",
				zap.String("name", vol.Name))
			continue
		}

		// Check size
		if vol.UsageData.Size > maxSizeBytes {
			logger.Info("Removing large volume",
				zap.String("name", vol.Name),
				zap.Int64("size", vol.UsageData.Size),
				zap.String("sizeHuman", formatBytes(vol.UsageData.Size)))

			if err := cli.VolumeRemove(rc.Ctx, vol.Name, false); err != nil {
				logger.Warn("Failed to remove volume",
					zap.String("name", vol.Name),
					zap.Error(err))
			} else {
				removedCount++
				totalReclaimed += vol.UsageData.Size
			}
		}
	}

	// EVALUATE
	logger.Info("Size-based volume pruning completed",
		zap.Int("removed", removedCount),
		zap.Int64("spaceReclaimed", totalReclaimed))

	return nil
}

// Helper functions

func getVolumesToPrune(rc *eos_io.RuntimeContext, cli *client.Client, config *PruneConfig) ([]*volume.Volume, error) {
	// List all volumes
	volumes, err := cli.VolumeList(rc.Ctx, volume.ListOptions{})
	if err != nil {
		return nil, err
	}

	volumesToPrune := make([]*volume.Volume, 0)

	for _, vol := range volumes.Volumes {
		// Skip if in keep list
		keep := false
		for _, keepVol := range config.KeepVolumes {
			if vol.Name == keepVol {
				keep = true
				break
			}
		}
		if keep {
			continue
		}

		// Check if unused
		if vol.UsageData == nil || vol.UsageData.RefCount == 0 || config.All {
			v := vol // Create a copy
			volumesToPrune = append(volumesToPrune, v)
		}
	}

	return volumesToPrune, nil
}

func isExcluded(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
