// pkg/zfs_management/zfs.go
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

// CheckZFSAvailable verifies that ZFS is available on the system following Assess → Intervene → Evaluate pattern
func CheckZFSAvailable(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS availability")

	// INTERVENE - Check if zpool command exists
	logger.Info("Checking for zpool command")
	if _, err := exec.LookPath("zpool"); err != nil {
		logger.Error("ZFS not available: zpool command not found")
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ZFS is not installed or not available in PATH"))
	}

	// Check if zfs command exists
	logger.Info("Checking for zfs command")
	if _, err := exec.LookPath("zfs"); err != nil {
		logger.Error("ZFS not available: zfs command not found")
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ZFS is not installed or not available in PATH"))
	}

	// EVALUATE
	logger.Info("ZFS commands are available")
	return nil
}

// ListZFSPools lists all ZFS pools following Assess → Intervene → Evaluate pattern
func ListZFSPools(rc *eos_io.RuntimeContext, config *ZFSConfig) (*ZFSListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS pool listing request")

	if config == nil {
		_ = DefaultZFSConfig()
	}

	if err := CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	// INTERVENE
	logger.Info("Listing ZFS pools")
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

	// EVALUATE
	logger.Info("ZFS pools listed successfully", zap.Int("count", len(pools)))
	return result, nil
}

// ListZFSFilesystems lists all ZFS filesystems following Assess → Intervene → Evaluate pattern
func ListZFSFilesystems(rc *eos_io.RuntimeContext, config *ZFSConfig) (*ZFSListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS filesystem listing request")

	if config == nil {
		_ = DefaultZFSConfig()
	}

	if err := CheckZFSAvailable(rc); err != nil {
		return nil, err
	}

	// INTERVENE
	logger.Info("Listing ZFS filesystems")
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

	// EVALUATE
	logger.Info("ZFS filesystems listed successfully", zap.Int("count", len(filesystems)))
	return result, nil
}

// ExpandZFSPool adds a device to an existing ZFS pool following Assess → Intervene → Evaluate pattern
func ExpandZFSPool(rc *eos_io.RuntimeContext, config *ZFSConfig, poolName, device string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS pool expansion request",
		zap.String("pool", poolName),
		zap.String("device", device))

	if config == nil {
		config = DefaultZFSConfig()
	}

	if err := CheckZFSAvailable(rc); err != nil {
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
		DryRun:    config.DryRun,
	}

	// INTERVENE
	if config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zpool add %s %s", poolName, device)
		logger.Info("Dry run: would expand pool", zap.String("command", result.Output))
		return result, nil
	}

	logger.Info("Expanding ZFS pool",
		zap.String("pool", poolName),
		zap.String("device", device))

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

	// EVALUATE
	logger.Info("ZFS pool expanded successfully",
		zap.String("pool", poolName),
		zap.String("device", device))

	return result, nil
}

// DestroyZFSPool destroys a ZFS pool following Assess → Intervene → Evaluate pattern
func DestroyZFSPool(rc *eos_io.RuntimeContext, config *ZFSConfig, poolName string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS pool destruction request",
		zap.String("pool", poolName))

	if config == nil {
		config = DefaultZFSConfig()
	}

	if err := CheckZFSAvailable(rc); err != nil {
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
		DryRun:    config.DryRun,
	}

	// Build command args
	args := []string{"destroy"}
	if config.Force {
		args = append(args, "-f")
	}
	args = append(args, poolName)

	// INTERVENE
	if config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zpool %s", strings.Join(args, " "))
		logger.Info("Dry run: would destroy pool", zap.String("command", result.Output))
		return result, nil
	}

	logger.Info("Destroying ZFS pool",
		zap.String("pool", poolName),
		zap.Bool("force", config.Force))

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

	// EVALUATE
	logger.Info("ZFS pool destroyed successfully", zap.String("pool", poolName))
	return result, nil
}

// DestroyZFSFilesystem destroys a ZFS filesystem following Assess → Intervene → Evaluate pattern
func DestroyZFSFilesystem(rc *eos_io.RuntimeContext, config *ZFSConfig, filesystemName string) (*ZFSOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS filesystem destruction request",
		zap.String("filesystem", filesystemName))

	if config == nil {
		config = DefaultZFSConfig()
	}

	if err := CheckZFSAvailable(rc); err != nil {
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
		DryRun:    config.DryRun,
	}

	// Build command args
	args := []string{"destroy"}
	if config.Recursive {
		args = append(args, "-r")
	}
	if config.Force {
		args = append(args, "-f")
	}
	args = append(args, filesystemName)

	// INTERVENE
	if config.DryRun {
		result.Success = true
		result.Output = fmt.Sprintf("Would execute: zfs %s", strings.Join(args, " "))
		logger.Info("Dry run: would destroy filesystem", zap.String("command", result.Output))
		return result, nil
	}

	logger.Info("Destroying ZFS filesystem",
		zap.String("filesystem", filesystemName),
		zap.Bool("recursive", config.Recursive))

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

	// EVALUATE
	logger.Info("ZFS filesystem destroyed successfully", zap.String("filesystem", filesystemName))
	return result, nil
}

// ValidateZFSPoolExists checks if a ZFS pool exists following Assess → Intervene → Evaluate pattern
func ValidateZFSPoolExists(rc *eos_io.RuntimeContext, config *ZFSConfig, poolName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS pool existence check", zap.String("pool", poolName))

	// INTERVENE
	result, err := ListZFSPools(rc, config)
	if err != nil {
		return false, err
	}

	for _, pool := range result.Pools {
		if pool.Name == poolName {
			// EVALUATE
			logger.Info("ZFS pool exists", zap.String("pool", poolName))
			return true, nil
		}
	}

	// EVALUATE
	logger.Info("ZFS pool does not exist", zap.String("pool", poolName))
	return false, nil
}

// ValidateZFSFilesystemExists checks if a ZFS filesystem exists following Assess → Intervene → Evaluate pattern
func ValidateZFSFilesystemExists(rc *eos_io.RuntimeContext, config *ZFSConfig, filesystemName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing ZFS filesystem existence check", zap.String("filesystem", filesystemName))

	// INTERVENE
	result, err := ListZFSFilesystems(rc, config)
	if err != nil {
		return false, err
	}

	for _, filesystem := range result.Filesystems {
		if filesystem.Name == filesystemName {
			// EVALUATE
			logger.Info("ZFS filesystem exists", zap.String("filesystem", filesystemName))
			return true, nil
		}
	}

	// EVALUATE
	logger.Info("ZFS filesystem does not exist", zap.String("filesystem", filesystemName))
	return false, nil
}
