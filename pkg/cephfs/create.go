package cephfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateVolume creates a new CephFS volume
func CreateVolume(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing CephFS prerequisites for volume creation",
		zap.String("volume", config.Name))

	// Check if ceph command is available
	if _, err := exec.LookPath("ceph"); err != nil {
		return eos_err.NewUserError("ceph command not found. Please install ceph-common package")
	}

	// Check if volume already exists
	checkCmd := exec.CommandContext(rc.Ctx, "ceph", "fs", "ls", "--format", "json")
	if output, err := checkCmd.Output(); err == nil {
		if strings.Contains(string(output), config.Name) {
			return eos_err.NewUserError("CephFS volume '%s' already exists", config.Name)
		}
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return eos_err.NewUserError("invalid configuration: %w", err)
	}

	// INTERVENE - Create the volume
	logger.Info("Creating CephFS volume",
		zap.String("volume", config.Name),
		zap.String("dataPool", config.DataPool),
		zap.String("metadataPool", config.MetadataPool))

	// Create data pool if specified
	if config.DataPool != "" {
		if err := createPool(rc, config.DataPool, config.PGNum); err != nil {
			return fmt.Errorf("failed to create data pool: %w", err)
		}
	}

	// Create metadata pool if specified
	if config.MetadataPool != "" {
		if err := createPool(rc, config.MetadataPool, config.PGNum/4); err != nil {
			// Rollback data pool creation
			deletePool(rc, config.DataPool)
			return fmt.Errorf("failed to create metadata pool: %w", err)
		}
	}

	// Create the CephFS volume
	createArgs := []string{"fs", "new", config.Name}
	if config.MetadataPool != "" {
		createArgs = append(createArgs, config.MetadataPool)
	}
	if config.DataPool != "" {
		createArgs = append(createArgs, config.DataPool)
	}

	createCmd := exec.CommandContext(rc.Ctx, "ceph", createArgs...)
	if output, err := createCmd.CombinedOutput(); err != nil {
		// Rollback pool creation
		deletePool(rc, config.DataPool)
		deletePool(rc, config.MetadataPool)
		return fmt.Errorf("failed to create CephFS volume: %w, output: %s", err, string(output))
	}

	// Set replication size if specified
	if config.ReplicationSize > 0 {
		if err := setReplication(rc, config); err != nil {
			logger.Warn("Failed to set replication size",
				zap.Error(err),
				zap.Int("size", config.ReplicationSize))
		}
	}

	// EVALUATE - Verify creation
	logger.Info("Verifying CephFS volume creation")

	// Check volume status
	statusCmd := exec.CommandContext(rc.Ctx, "ceph", "fs", "status", config.Name, "--format", "json")
	if output, err := statusCmd.Output(); err != nil {
		return fmt.Errorf("failed to verify volume creation: %w", err)
	} else {
		logger.Debug("Volume status retrieved",
			zap.String("status", string(output)))
	}

	// Check MDS status
	mdsCmd := exec.CommandContext(rc.Ctx, "ceph", "mds", "stat", "--format", "json")
	if output, err := mdsCmd.Output(); err != nil {
		logger.Warn("Failed to check MDS status",
			zap.Error(err))
	} else {
		logger.Debug("MDS status",
			zap.String("status", string(output)))
	}

	logger.Info("CephFS volume created successfully",
		zap.String("volume", config.Name))

	return nil
}

// CreateMountPoint creates and mounts a CephFS volume
func CreateMountPoint(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate mount point path
	if err := validateMountPath(config.MountPoint); err != nil {
		return err
	}

	// ASSESS
	logger.Info("Assessing mount point requirements",
		zap.String("mountPoint", config.MountPoint))

	// Check if mount point exists
	if _, err := os.Stat(config.MountPoint); os.IsNotExist(err) {
		logger.Debug("Creating mount point directory")
		if err := os.MkdirAll(config.MountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point: %w", err)
		}
	}

	// Check if already mounted
	if isMounted(rc, config.MountPoint) {
		return eos_err.NewUserError("path %s is already mounted", config.MountPoint)
	}

	// INTERVENE - Mount the volume
	logger.Info("Mounting CephFS volume",
		zap.String("volume", config.Name),
		zap.String("mountPoint", config.MountPoint))

	// Build mount command
	mountArgs := buildMountArgs(config)
	mountCmd := exec.CommandContext(rc.Ctx, "mount", mountArgs...)

	if output, err := mountCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount CephFS: %w, output: %s", err, string(output))
	}

	// Add to fstab if requested
	if shouldPersistMount(config) {
		if err := addToFstab(rc, config); err != nil {
			logger.Warn("Failed to add mount to fstab",
				zap.Error(err))
		}
	}

	// EVALUATE
	logger.Info("Verifying mount")

	if !isMounted(rc, config.MountPoint) {
		return fmt.Errorf("mount verification failed: volume not mounted at %s", config.MountPoint)
	}

	// Test write access
	testFile := filepath.Join(config.MountPoint, ".eos_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		logger.Warn("Mount point is read-only",
			zap.String("mountPoint", config.MountPoint))
	} else {
		_ = os.Remove(testFile)
		logger.Debug("Mount point is writable")
	}

	logger.Info("CephFS mounted successfully",
		zap.String("mountPoint", config.MountPoint))

	return nil
}

// Helper functions

func validateConfig(config *Config) error {
	if config.Name == "" {
		return fmt.Errorf("volume name is required")
	}

	if config.ReplicationSize < 0 || config.ReplicationSize > 10 {
		return fmt.Errorf("replication size must be between 1 and 10")
	}

	if config.PGNum < 0 || config.PGNum > 32768 {
		return fmt.Errorf("PG number must be between 1 and 32768")
	}

	return nil
}

func createPool(rc *eos_io.RuntimeContext, poolName string, pgNum int) error {
	logger := otelzap.Ctx(rc.Ctx)

	if pgNum == 0 {
		pgNum = DefaultPGNum
	}

	logger.Debug("Creating Ceph pool",
		zap.String("pool", poolName),
		zap.Int("pgNum", pgNum))

	createCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "create", poolName, fmt.Sprintf("%d", pgNum))
	if output, err := createCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create pool %s: %w, output: %s", poolName, err, string(output))
	}

	// Enable application
	appCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "application", "enable", poolName, "cephfs")
	if err := appCmd.Run(); err != nil {
		logger.Warn("Failed to enable cephfs application on pool",
			zap.String("pool", poolName),
			zap.Error(err))
	}

	return nil
}

func deletePool(rc *eos_io.RuntimeContext, poolName string) {
	if poolName == "" {
		return
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Deleting pool as part of rollback",
		zap.String("pool", poolName))

	// Ceph requires confirmation for pool deletion
	deleteCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "delete", poolName, poolName, "--yes-i-really-really-mean-it")
	if err := deleteCmd.Run(); err != nil {
		logger.Warn("Failed to delete pool during rollback",
			zap.String("pool", poolName),
			zap.Error(err))
	}
}

func setReplication(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	pools := []string{}
	if config.DataPool != "" {
		pools = append(pools, config.DataPool)
	}
	if config.MetadataPool != "" {
		pools = append(pools, config.MetadataPool)
	}

	for _, pool := range pools {
		logger.Debug("Setting replication size",
			zap.String("pool", pool),
			zap.Int("size", config.ReplicationSize))

		sizeCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "set", pool, "size", fmt.Sprintf("%d", config.ReplicationSize))
		if err := sizeCmd.Run(); err != nil {
			return fmt.Errorf("failed to set replication size for pool %s: %w", pool, err)
		}

		// Set min_size to size-1 for better availability
		minSize := config.ReplicationSize - 1
		if minSize < 1 {
			minSize = 1
		}

		minSizeCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "set", pool, "min_size", fmt.Sprintf("%d", minSize))
		if err := minSizeCmd.Run(); err != nil {
			logger.Warn("Failed to set min_size",
				zap.String("pool", pool),
				zap.Error(err))
		}
	}

	return nil
}

func isMounted(rc *eos_io.RuntimeContext, mountPoint string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	mountCmd := exec.CommandContext(rc.Ctx, "findmnt", "-n", mountPoint)
	if err := mountCmd.Run(); err != nil {
		logger.Debug("Mount point not found",
			zap.String("mountPoint", mountPoint))
		return false
	}

	return true
}

func buildMountArgs(config *Config) []string {
	args := []string{"-t", "ceph"}

	// Build monitor string
	monString := strings.Join(config.MonitorHosts, ",") + ":/"
	if config.Name != "" {
		monString += config.Name
	}
	args = append(args, monString, config.MountPoint)

	// Add mount options
	options := []string{"name=" + config.User}
	if config.SecretFile != "" {
		options = append(options, "secretfile="+config.SecretFile)
	}
	options = append(options, config.MountOptions...)

	if len(options) > 0 {
		args = append(args, "-o", strings.Join(options, ","))
	}

	return args
}

func shouldPersistMount(config *Config) bool {
	// Check if any mount option indicates persistence
	for _, opt := range config.MountOptions {
		if opt == "_netdev" || opt == "auto" {
			return true
		}
	}
	return false
}

func addToFstab(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding CephFS mount to /etc/fstab")

	// Build fstab entry
	monString := strings.Join(config.MonitorHosts, ",") + ":/"
	if config.Name != "" {
		monString += config.Name
	}

	options := append([]string{"name=" + config.User}, config.MountOptions...)
	if config.SecretFile != "" {
		options = append(options, "secretfile="+config.SecretFile)
	}

	entry := fmt.Sprintf("%s %s ceph %s 0 0\n",
		monString,
		config.MountPoint,
		strings.Join(options, ","))

	// Append to fstab
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open /etc/fstab: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("Warning: Failed to close file: %v\n", err)
		}
	}()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to /etc/fstab: %w", err)
	}

	logger.Debug("Added fstab entry",
		zap.String("entry", strings.TrimSpace(entry)))

	return nil
}

// validateMountPath validates that a mount path is safe to use
func validateMountPath(path string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("mount path cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("mount path cannot contain '..' (path traversal)")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("mount path cannot contain null bytes")
	}

	// Check for control characters
	if strings.ContainsAny(path, "\n\r\t") {
		return fmt.Errorf("mount path cannot contain control characters")
	}

	// Ensure path is absolute
	if !filepath.IsAbs(path) {
		return fmt.Errorf("mount path must be absolute (start with /)")
	}

	// Clean the path and check it hasn't changed (prevents various injection attempts)
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("mount path contains unsafe elements")
	}

	// Check for sensitive system paths
	sensitivePaths := []string{"/", "/etc", "/boot", "/dev", "/proc", "/sys", "/root"}
	for _, sensitive := range sensitivePaths {
		if cleanPath == sensitive || strings.HasPrefix(cleanPath, sensitive+"/") {
			return fmt.Errorf("cannot mount on sensitive system path: %s", sensitive)
		}
	}

	// Check path length limit
	if len(path) > 4096 {
		return fmt.Errorf("mount path too long (max 4096 characters)")
	}

	return nil
}
