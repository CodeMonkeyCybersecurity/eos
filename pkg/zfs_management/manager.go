package zfs_management

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ZFSManager handles ZFS operations
type ZFSManager struct {
	config *ZFSConfig
}

// NewZFSManager creates a new ZFS manager
func NewZFSManager(config *ZFSConfig) *ZFSManager {
	if config == nil {
		config = DefaultZFSConfig()
	}

	return &ZFSManager{
		config: config,
	}
}

// CheckZFSAvailable verifies that ZFS is available on the system
func (zm *ZFSManager) CheckZFSAvailable(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if zpool command exists
	if _, err := exec.LookPath("zpool"); err != nil {
		logger.Error("ZFS not available: zpool command not found")
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ZFS is not installed or not available in PATH"))
	}

	// Check if zfs command exists
	if _, err := exec.LookPath("zfs"); err != nil {
		logger.Error("ZFS not available: zfs command not found")
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ZFS is not installed or not available in PATH"))
	}

	logger.Info("ZFS commands are available")
	return nil
}

// ListPools lists all ZFS pools
func (zm *ZFSManager) ListPools(rc *eos_io.RuntimeContext) (*ZFSListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing ZFS pools")

	if err := zm.CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(rc.Ctx, "zpool", "list", "-H", "-o", "name,size,alloc,free,frag,cap,dedup,health,altroot")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			// No pools exist
			logger.Info("No ZFS pools found")
			return &ZFSListResult{
				Timestamp: time.Now(),
				Pools:     []ZFSPool{},
				Count:     0,
			}, nil
		}
		logger.Error("Failed to list ZFS pools", zap.Error(err))
		return nil, fmt.Errorf("failed to list ZFS pools: %w", err)
	}

	pools := make([]ZFSPool, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 9 {
			pool := ZFSPool{
				Name:    fields[0],
				Size:    fields[1],
				Alloc:   fields[2],
				Free:    fields[3],
				Frag:    fields[4],
				Cap:     fields[5],
				Dedup:   fields[6],
				Health:  fields[7],
				AltRoot: fields[8],
			}

			// Clean up fields that might show "-" for empty values
			if pool.AltRoot == "-" {
				pool.AltRoot = ""
			}

			pools = append(pools, pool)
		}
	}

	result := &ZFSListResult{
		Timestamp: time.Now(),
		Pools:     pools,
		Count:     len(pools),
	}

	logger.Info("Found ZFS pools", zap.Int("count", len(pools)))
	return result, nil
}

// ListFilesystems lists all ZFS filesystems
func (zm *ZFSManager) ListFilesystems(rc *eos_io.RuntimeContext) (*ZFSListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing ZFS filesystems")

	if err := zm.CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(rc.Ctx, "zfs", "list", "-H", "-o", "name,used,avail,refer,mountpoint,type")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			// No filesystems exist
			logger.Info("No ZFS filesystems found")
			return &ZFSListResult{
				Timestamp:   time.Now(),
				Filesystems: []ZFSFilesystem{},
				Count:       0,
			}, nil
		}
		logger.Error("Failed to list ZFS filesystems", zap.Error(err))
		return nil, fmt.Errorf("failed to list ZFS filesystems: %w", err)
	}

	filesystems := make([]ZFSFilesystem, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 6 {
			filesystem := ZFSFilesystem{
				Name:       fields[0],
				Used:       fields[1],
				Available:  fields[2],
				Refer:      fields[3],
				Mountpoint: fields[4],
				Type:       fields[5],
			}

			// Clean up fields that might show "-" for empty values
			if filesystem.Mountpoint == "-" {
				filesystem.Mountpoint = ""
			}

			filesystems = append(filesystems, filesystem)
		}
	}

	result := &ZFSListResult{
		Timestamp:   time.Now(),
		Filesystems: filesystems,
		Count:       len(filesystems),
	}

	logger.Info("Found ZFS filesystems", zap.Int("count", len(filesystems)))
	return result, nil
}

// ExpandPool adds a device to an existing ZFS pool
func (zm *ZFSManager) ExpandPool(rc *eos_io.RuntimeContext, poolName, device string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Expanding ZFS pool",
		zap.String("pool", poolName),
		zap.String("device", device),
		zap.Bool("dry_run", zm.config.DryRun))

	if err := zm.CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	// Validate inputs
	if poolName == "" {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("pool name cannot be empty"))
	}
	if device == "" {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("device cannot be empty"))
	}

	result := &ZFSOperationResult{
		Timestamp: time.Now(),
		Operation: "expand_pool",
		Target:    fmt.Sprintf("%s + %s", poolName, device),
		DryRun:    zm.config.DryRun,
	}

	if zm.config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zpool add %s %s", poolName, device)
		logger.Info("Dry run: would expand pool", zap.String("command", result.Output))
		return result, nil
	}

	// Execute the expand operation
	cmd := exec.CommandContext(rc.Ctx, "zpool", "add", poolName, device)
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		logger.Error("Failed to expand ZFS pool",
			zap.Error(err),
			zap.String("output", result.Output))
		return result, fmt.Errorf("failed to expand pool %s: %w", poolName, err)
	}

	result.Success = true
	logger.Info("Successfully expanded ZFS pool",
		zap.String("pool", poolName),
		zap.String("device", device))

	return result, nil
}

// DestroyPool destroys a ZFS pool
func (zm *ZFSManager) DestroyPool(rc *eos_io.RuntimeContext, poolName string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Destroying ZFS pool",
		zap.String("pool", poolName),
		zap.Bool("dry_run", zm.config.DryRun),
		zap.Bool("force", zm.config.Force))

	if err := zm.CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	// Validate inputs
	if poolName == "" {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("pool name cannot be empty"))
	}

	result := &ZFSOperationResult{
		Timestamp: time.Now(),
		Operation: "destroy_pool",
		Target:    poolName,
		DryRun:    zm.config.DryRun,
	}

	// Build command args
	args := []string{"destroy"}
	if zm.config.Force {
		args = append(args, "-f")
	}
	args = append(args, poolName)

	if zm.config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zpool %s", strings.Join(args, " "))
		logger.Info("Dry run: would destroy pool", zap.String("command", result.Output))
		return result, nil
	}

	// Execute the destroy operation
	cmd := exec.CommandContext(rc.Ctx, "zpool", args...)
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		logger.Error("Failed to destroy ZFS pool",
			zap.Error(err),
			zap.String("output", result.Output))
		return result, fmt.Errorf("failed to destroy pool %s: %w", poolName, err)
	}

	result.Success = true
	logger.Info("Successfully destroyed ZFS pool", zap.String("pool", poolName))

	return result, nil
}

// DestroyFilesystem destroys a ZFS filesystem
func (zm *ZFSManager) DestroyFilesystem(rc *eos_io.RuntimeContext, filesystemName string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Destroying ZFS filesystem",
		zap.String("filesystem", filesystemName),
		zap.Bool("dry_run", zm.config.DryRun),
		zap.Bool("recursive", zm.config.Recursive))

	if err := zm.CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	// Validate inputs
	if filesystemName == "" {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("filesystem name cannot be empty"))
	}

	result := &ZFSOperationResult{
		Timestamp: time.Now(),
		Operation: "destroy_filesystem",
		Target:    filesystemName,
		DryRun:    zm.config.DryRun,
	}

	// Build command args
	args := []string{"destroy"}
	if zm.config.Recursive {
		args = append(args, "-r")
	}
	if zm.config.Force {
		args = append(args, "-f")
	}
	args = append(args, filesystemName)

	if zm.config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zfs %s", strings.Join(args, " "))
		logger.Info("Dry run: would destroy filesystem", zap.String("command", result.Output))
		return result, nil
	}

	// Execute the destroy operation
	cmd := exec.CommandContext(rc.Ctx, "zfs", args...)
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		logger.Error("Failed to destroy ZFS filesystem",
			zap.Error(err),
			zap.String("output", result.Output))
		return result, fmt.Errorf("failed to destroy filesystem %s: %w", filesystemName, err)
	}

	result.Success = true
	logger.Info("Successfully destroyed ZFS filesystem", zap.String("filesystem", filesystemName))

	return result, nil
}

// ValidatePoolExists checks if a ZFS pool exists
func (zm *ZFSManager) ValidatePoolExists(rc *eos_io.RuntimeContext, poolName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result, err := zm.ListPools(rc)
	if err != nil {
		return false, err
	}

	for _, pool := range result.Pools {
		if pool.Name == poolName {
			logger.Info("Pool exists", zap.String("pool", poolName))
			return true, nil
		}
	}

	logger.Info("Pool does not exist", zap.String("pool", poolName))
	return false, nil
}

// ValidateFilesystemExists checks if a ZFS filesystem exists
func (zm *ZFSManager) ValidateFilesystemExists(rc *eos_io.RuntimeContext, filesystemName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result, err := zm.ListFilesystems(rc)
	if err != nil {
		return false, err
	}

	for _, filesystem := range result.Filesystems {
		if filesystem.Name == filesystemName {
			logger.Info("Filesystem exists", zap.String("filesystem", filesystemName))
			return true, nil
		}
	}

	logger.Info("Filesystem does not exist", zap.String("filesystem", filesystemName))
	return false, nil
}
