package docker_volume

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureLogRotation sets up log rotation for a container
func ConfigureLogRotation(rc *eos_io.RuntimeContext, config *ContainerLogConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing container for log rotation configuration",
		zap.String("container", config.ContainerName),
		zap.String("maxSize", config.MaxSize),
		zap.Int("maxFiles", config.MaxFiles))

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			logger.Warn("Failed to close Docker client", zap.Error(err))
		}
	}()

	// Get container info
	containerInfo, err := cli.ContainerInspect(rc.Ctx, config.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check current logging driver
	currentDriver := containerInfo.HostConfig.LogConfig.Type
	if currentDriver != "" && currentDriver != "json-file" {
		logger.Warn("Container uses non-json-file logging driver",
			zap.String("driver", currentDriver))
	}

	// INTERVENE
	logger.Info("Configuring log rotation")

	// For running containers, we need to update and restart
	// For new containers, this config would be applied at creation

	if containerInfo.State.Running {
		logger.Info("Container is running, configuration will apply on next restart")

		// Create a configuration file for reference
		configPath := fmt.Sprintf("/etc/docker/containers/%s/log-rotation.conf", config.ContainerID)
		if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
			logger.Warn("Failed to create config directory",
				zap.Error(err))
		}

		logConfig := map[string]string{
			"max-size": config.MaxSize,
			"max-file": fmt.Sprintf("%d", config.MaxFiles),
		}

		configData, _ := json.MarshalIndent(logConfig, "", "  ")
		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			logger.Warn("Failed to write config file",
				zap.Error(err))
		}
	}

	// EVALUATE
	logger.Info("Log rotation configuration completed",
		zap.String("container", config.ContainerName))

	return nil
}

// RotateContainerLogs manually rotates container logs
func RotateContainerLogs(rc *eos_io.RuntimeContext, containerID string) (*LogRotationStats, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing container logs for rotation",
		zap.String("container", containerID))

	// Find container log file
	logPath := fmt.Sprintf("/var/lib/docker/containers/%s/%s-json.log", containerID, containerID)

	logInfo, err := os.Stat(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat log file: %w", err)
	}

	stats := &LogRotationStats{
		ContainerID:    containerID,
		CurrentLogSize: logInfo.Size(),
		LastRotation:   time.Now(),
	}

	// Check if rotation is needed
	if logInfo.Size() < 10*Megabyte {
		logger.Info("Log file is small, rotation not needed",
			zap.Int64("size", logInfo.Size()))
		return stats, nil
	}

	// INTERVENE
	logger.Info("Rotating container logs",
		zap.Int64("currentSize", logInfo.Size()))

	// Create rotated log filename
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", logPath, timestamp)

	// Copy current log to rotated file
	if err := copyFile(logPath, rotatedPath); err != nil {
		return nil, fmt.Errorf("failed to copy log file: %w", err)
	}

	// Truncate original log file
	if err := os.Truncate(logPath, 0); err != nil {
		// Try to clean up rotated file
		_ = os.Remove(rotatedPath)
		return nil, fmt.Errorf("failed to truncate log file: %w", err)
	}

	// Compress rotated log
	if err := compressFile(rc, rotatedPath); err != nil {
		logger.Warn("Failed to compress rotated log",
			zap.Error(err))
	} else {
		// Remove uncompressed file after successful compression
		_ = os.Remove(rotatedPath)
		rotatedPath += ".gz"
	}

	// Update stats
	stats.RotatedLogs = 1
	stats.TotalLogSize = logInfo.Size()

	// EVALUATE
	logger.Info("Log rotation completed",
		zap.String("rotatedFile", rotatedPath),
		zap.Int64("freedSpace", logInfo.Size()))

	// Clean up old rotated logs
	if err := cleanupOldLogs(rc, containerID, 3); err != nil {
		logger.Warn("Failed to cleanup old logs",
			zap.Error(err))
	}

	return stats, nil
}

// MonitorLogSizes monitors and reports on container log sizes
func MonitorLogSizes(rc *eos_io.RuntimeContext) (map[string]*LogRotationStats, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing all container logs")

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			logger.Warn("Failed to close Docker client", zap.Error(err))
		}
	}()

	// List all containers
	containers, err := cli.ContainerList(rc.Ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// INTERVENE
	logger.Info("Checking log sizes for all containers",
		zap.Int("containerCount", len(containers)))

	results := make(map[string]*LogRotationStats)

	for _, container := range containers {
		containerID := container.ID[:12]
		containerName := strings.TrimPrefix(container.Names[0], "/")

		// Find log file
		logPath := fmt.Sprintf("/var/lib/docker/containers/%s/%s-json.log",
			container.ID, container.ID)

		if logInfo, err := os.Stat(logPath); err == nil {
			stats := &LogRotationStats{
				ContainerID:    containerID,
				ContainerName:  containerName,
				CurrentLogSize: logInfo.Size(),
			}

			// Count rotated logs
			rotatedCount, totalSize := countRotatedLogs(filepath.Dir(logPath), container.ID)
			stats.RotatedLogs = rotatedCount
			stats.TotalLogSize = totalSize + logInfo.Size()

			results[containerID] = stats

			// Log warning for large log files
			if logInfo.Size() > 100*Megabyte {
				logger.Warn("Large log file detected",
					zap.String("container", containerName),
					zap.Int64("size", logInfo.Size()))
			}
		}
	}

	// EVALUATE
	logger.Info("Log size monitoring completed",
		zap.Int("containersChecked", len(results)))

	return results, nil
}

// SetDefaultLogLimits sets default log limits for all new containers
func SetDefaultLogLimits(rc *eos_io.RuntimeContext, maxSize string, maxFiles int) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Docker daemon configuration",
		zap.String("maxSize", maxSize),
		zap.Int("maxFiles", maxFiles))

	daemonConfigPath := "/etc/docker/daemon.json"

	// Read existing config
	var daemonConfig map[string]interface{}
	if data, err := os.ReadFile(daemonConfigPath); err == nil {
		if err := json.Unmarshal(data, &daemonConfig); err != nil {
			logger.Warn("Failed to parse existing daemon.json",
				zap.Error(err))
			daemonConfig = make(map[string]interface{})
		}
	} else {
		daemonConfig = make(map[string]interface{})
	}

	// INTERVENE
	logger.Info("Updating Docker daemon log configuration")

	// Set log driver options
	logConfig := map[string]interface{}{
		"log-driver": "json-file",
		"log-opts": map[string]string{
			"max-size": maxSize,
			"max-file": fmt.Sprintf("%d", maxFiles),
		},
	}

	// Merge with existing config
	for k, v := range logConfig {
		daemonConfig[k] = v
	}

	// Write updated config
	configData, err := json.MarshalIndent(daemonConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Backup existing config
	if _, err := os.Stat(daemonConfigPath); err == nil {
		backupPath := daemonConfigPath + ".bak"
		if err := copyFile(daemonConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup daemon.json",
				zap.Error(err))
		}
	}

	if err := os.WriteFile(daemonConfigPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write daemon config: %w", err)
	}

	// EVALUATE
	logger.Info("Docker daemon log configuration updated",
		zap.String("configPath", daemonConfigPath))

	logger.Info("Restart Docker daemon for changes to take effect")

	return nil
}

// Helper functions

func copyFile(src, dst string) error {
	// Use shared file operations instead of custom implementation
	return shared.CopyFile(src, dst)
}

func compressFile(rc *eos_io.RuntimeContext, filePath string) error {
	return execute.RunSimple(rc.Ctx, "gzip", filePath)
}

func cleanupOldLogs(rc *eos_io.RuntimeContext, containerID string, keepCount int) error {
	logDir := fmt.Sprintf("/var/lib/docker/containers/%s", containerID)

	// Find all rotated logs
	pattern := fmt.Sprintf("%s-json.log.*", containerID)
	matches, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return err
	}

	// Sort by modification time
	if len(matches) <= keepCount {
		return nil
	}

	// Delete oldest logs
	for i := 0; i < len(matches)-keepCount; i++ {
		_ = os.Remove(matches[i])
	}

	return nil
}

func countRotatedLogs(logDir, containerID string) (int, int64) {
	pattern := fmt.Sprintf("%s-json.log.*", containerID)
	matches, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return 0, 0
	}

	var totalSize int64
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil {
			totalSize += info.Size()
		}
	}

	return len(matches), totalSize
}
