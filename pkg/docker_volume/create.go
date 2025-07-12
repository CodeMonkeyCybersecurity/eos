package docker_volume

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateVolume creates a new Docker volume
func CreateVolume(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Docker volume creation requirements",
		zap.String("name", config.Name),
		zap.String("driver", config.Driver))

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			fmt.Printf("Warning: Failed to close Docker client: %v\n", err)
		}
	}()

	// Check if volume already exists
	volumes, err := cli.VolumeList(rc.Ctx, volume.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list volumes: %w", err)
	}

	for _, v := range volumes.Volumes {
		if v.Name == config.Name {
			return eos_err.NewUserError("volume %s already exists", config.Name)
		}
	}

	// Validate driver
	if config.Driver == "" {
		config.Driver = DriverLocal
	}

	// INTERVENE
	logger.Info("Creating Docker volume",
		zap.String("name", config.Name),
		zap.Any("driverOpts", config.DriverOpts))

	// Create volume
	createOpts := volume.CreateOptions{
		Name:       config.Name,
		Driver:     config.Driver,
		DriverOpts: config.DriverOpts,
		Labels:     config.Labels,
	}

	vol, err := cli.VolumeCreate(rc.Ctx, createOpts)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	logger.Debug("Volume created",
		zap.String("mountpoint", vol.Mountpoint),
		zap.String("scope", vol.Scope))

	// EVALUATE
	logger.Info("Verifying volume creation")

	// Inspect the created volume
	volInfo, err := cli.VolumeInspect(rc.Ctx, config.Name)
	if err != nil {
		return fmt.Errorf("volume verification failed: %w", err)
	}

	if volInfo.Name != config.Name {
		return fmt.Errorf("volume verification failed: name mismatch")
	}

	logger.Info("Docker volume created successfully",
		zap.String("name", volInfo.Name),
		zap.String("driver", volInfo.Driver),
		zap.String("mountpoint", volInfo.Mountpoint))

	return nil
}

// CreateBindMount creates a bind mount configuration
func CreateBindMount(rc *eos_io.RuntimeContext, mount *BindMount) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing bind mount requirements",
		zap.String("source", mount.Source),
		zap.String("target", mount.Target))

	// Check if source exists
	sourceInfo, err := os.Stat(mount.Source)
	if err != nil {
		if os.IsNotExist(err) {
			// Create source directory if it doesn't exist
			logger.Debug("Creating source directory")
			if err := os.MkdirAll(mount.Source, 0755); err != nil {
				return fmt.Errorf("failed to create source directory: %w", err)
			}
		} else {
			return fmt.Errorf("failed to stat source: %w", err)
		}
	}

	// Validate mount type
	if mount.Type == "" {
		mount.Type = "bind"
	}

	// INTERVENE
	logger.Info("Configuring bind mount",
		zap.Bool("readOnly", mount.ReadOnly),
		zap.String("consistency", mount.Consistency))

	// For bind mounts, we primarily validate and prepare the configuration
	// The actual mounting happens when a container uses this configuration

	// Set appropriate permissions if needed
	if sourceInfo != nil && sourceInfo.IsDir() {
		// Ensure directory has appropriate permissions
		if err := os.Chmod(mount.Source, 0755); err != nil {
			logger.Warn("Failed to set directory permissions",
				zap.Error(err))
		}
	}

	// Create a marker file to indicate this is a Docker bind mount
	markerPath := filepath.Join(mount.Source, ".docker-bind-mount")
	if err := os.WriteFile(markerPath, []byte(fmt.Sprintf("target=%s\n", mount.Target)), 0644); err != nil {
		logger.Debug("Failed to create marker file",
			zap.Error(err))
	}

	// EVALUATE
	logger.Info("Bind mount configuration prepared",
		zap.String("source", mount.Source),
		zap.String("target", mount.Target))

	return nil
}

// CreateNamedVolume creates a named volume with specific characteristics
func CreateNamedVolume(rc *eos_io.RuntimeContext, name string, sizeLimit string, filesystem string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing named volume creation with size limit",
		zap.String("name", name),
		zap.String("sizeLimit", sizeLimit),
		zap.String("filesystem", filesystem))

	// Parse size limit
	sizeBytes, err := parseSize(sizeLimit)
	if err != nil {
		return eos_err.NewUserError("invalid size format: %s", sizeLimit)
	}

	// INTERVENE
	logger.Info("Creating named volume with constraints")

	// For size-limited volumes, we might use a different driver or options
	driverOpts := make(map[string]string)

	if sizeBytes > 0 {
		// Use device mapper or other driver that supports size limits
		driverOpts["size"] = sizeLimit
	}

	if filesystem != "" && filesystem != "ext4" {
		driverOpts["type"] = filesystem
	}

	config := &Config{
		Name:       name,
		Driver:     DriverLocal,
		DriverOpts: driverOpts,
		Labels: map[string]string{
			"eos.size_limit": sizeLimit,
			"eos.filesystem": filesystem,
		},
	}

	if err := CreateVolume(rc, config); err != nil {
		return err
	}

	// EVALUATE
	logger.Info("Named volume created with constraints",
		zap.String("name", name),
		zap.Int64("sizeBytes", sizeBytes))

	return nil
}

// Helper functions

func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	multiplier := int64(1)
	numStr := sizeStr

	if strings.HasSuffix(sizeStr, "G") || strings.HasSuffix(sizeStr, "GB") {
		multiplier = Gigabyte
		numStr = strings.TrimSuffix(strings.TrimSuffix(sizeStr, "GB"), "G")
	} else if strings.HasSuffix(sizeStr, "M") || strings.HasSuffix(sizeStr, "MB") {
		multiplier = Megabyte
		numStr = strings.TrimSuffix(strings.TrimSuffix(sizeStr, "MB"), "M")
	} else if strings.HasSuffix(sizeStr, "K") || strings.HasSuffix(sizeStr, "KB") {
		multiplier = Kilobyte
		numStr = strings.TrimSuffix(strings.TrimSuffix(sizeStr, "KB"), "K")
	}

	var num int64
	if _, err := fmt.Sscanf(numStr, "%d", &num); err != nil {
		return 0, err
	}

	return num * multiplier, nil
}
