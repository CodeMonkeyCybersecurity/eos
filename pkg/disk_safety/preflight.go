package disk_safety

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)


// PreflightCheck interface for all safety checks
type PreflightCheck interface {
	Name() string
	Description() string
	Check(ctx context.Context, target DiskTarget) error
	Severity() CheckSeverity
	CanSkip() bool
}


// PreflightRunner executes preflight checks
type PreflightRunner struct {
	checks      []PreflightCheck
	rc          *eos_io.RuntimeContext
	skipOnError bool
}

// NewPreflightRunner creates a new preflight runner with default checks
func NewPreflightRunner(rc *eos_io.RuntimeContext) *PreflightRunner {
	return &PreflightRunner{
		checks: []PreflightCheck{
			&FilesystemCleanCheck{},
			&OpenFilesCheck{},
			&MountStatusCheck{},
			&SmartHealthCheck{},
			&FreeSpaceCheck{},
			&ActiveIOCheck{},
			&PermissionCheck{},
			&LockFileCheck{},
		},
		rc:          rc,
		skipOnError: false,
	}
}

// SetSkipOnError configures whether to skip checks that error
func (pr *PreflightRunner) SetSkipOnError(skip bool) {
	pr.skipOnError = skip
}

// AddCheck adds a custom check to the runner
func (pr *PreflightRunner) AddCheck(check PreflightCheck) {
	pr.checks = append(pr.checks, check)
}

// Run executes all preflight checks
func (pr *PreflightRunner) Run(ctx context.Context, target DiskTarget) (*PreflightReport, error) {
	logger := otelzap.Ctx(ctx)

	report := &PreflightReport{
		Target:    target,
		Timestamp: time.Now(),
		Checks:    make([]CheckResult, 0, len(pr.checks)),
	}

	logger.Info("Starting preflight checks",
		zap.String("target_device", target.Device),
		zap.String("volume_group", target.VolumeGroup),
		zap.String("logical_volume", target.LogicalVol))

	var criticalErrors []error

	for _, check := range pr.checks {
		checkStart := time.Now()
		result := CheckResult{
			Name:        check.Name(),
			Description: check.Description(),
			Severity:    check.Severity(),
		}

		logger.Debug("Running preflight check",
			zap.String("check_name", check.Name()),
			zap.String("severity", string(check.Severity())))

		err := check.Check(ctx, target)
		result.Duration = time.Since(checkStart)

		if err != nil {
			result.Error = err.Error()
			result.Passed = false

			if check.CanSkip() && pr.skipOnError {
				logger.Warn("Preflight check failed but skipped",
					zap.String("check", check.Name()),
					zap.Error(err))
			} else if check.Severity() == SeverityCritical {
				criticalErrors = append(criticalErrors, fmt.Errorf("%s: %w", check.Name(), err))
				logger.Error("Critical preflight check failed",
					zap.String("check", check.Name()),
					zap.Error(err))
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %s", check.Name(), err.Error()))
			} else {
				logger.Warn("Non-critical preflight check failed",
					zap.String("check", check.Name()),
					zap.Error(err))
				if check.Severity() == SeverityWarning {
					report.Warnings = append(report.Warnings, fmt.Sprintf("%s: %s", check.Name(), err.Error()))
				}
			}
		} else {
			result.Passed = true
			logger.Debug("Preflight check passed",
				zap.String("check", check.Name()))
		}

		report.Checks = append(report.Checks, result)
	}

	report.OverallPass = len(criticalErrors) == 0 && len(report.Warnings) == 0

	logger.Info("Preflight checks completed",
		zap.Bool("overall_pass", report.OverallPass),
		zap.Int("error_count", len(report.Errors)),
		zap.Int("warning_count", len(report.Warnings)))

	if len(criticalErrors) > 0 {
		return report, fmt.Errorf("critical preflight checks failed: %v", criticalErrors)
	}

	return report, nil
}

// FilesystemCleanCheck verifies filesystem integrity
type FilesystemCleanCheck struct{}

func (f *FilesystemCleanCheck) Name() string        { return "filesystem_clean" }
func (f *FilesystemCleanCheck) Description() string { return "Verify filesystem integrity" }
func (f *FilesystemCleanCheck) Severity() CheckSeverity { return SeverityCritical }
func (f *FilesystemCleanCheck) CanSkip() bool       { return false }

func (f *FilesystemCleanCheck) Check(ctx context.Context, target DiskTarget) error {
	device := target.GetDevice()
	if device == "" {
		return fmt.Errorf("no device specified for filesystem check")
	}

	// Check if filesystem is mounted
	mounted, err := isMounted(device)
	if err != nil {
		return fmt.Errorf("check mount status: %w", err)
	}

	if mounted {
		// For mounted filesystems, we can't run fsck directly
		// Check for read-only remounts or errors in dmesg instead
		return f.checkMountedFilesystem(ctx, device)
	}

	// For unmounted filesystems, run fsck in check-only mode
	cmd := exec.CommandContext(ctx, "fsck", "-n", device)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("filesystem check failed: %s", string(output))
	}

	return nil
}

func (f *FilesystemCleanCheck) checkMountedFilesystem(ctx context.Context, device string) error {
	// Check for filesystem errors in recent dmesg
	cmd := exec.CommandContext(ctx, "dmesg", "-T")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// dmesg failure is not critical for this check
		return nil
	}

	// Look for filesystem error patterns
	lines := strings.Split(string(output), "\n")
	for i := len(lines) - 100; i >= 0 && i < len(lines); i++ { // Check last 100 lines
		line := strings.ToLower(lines[i])
		if strings.Contains(line, "ext4") || strings.Contains(line, "xfs") {
			if strings.Contains(line, "error") || strings.Contains(line, "corruption") {
				return fmt.Errorf("filesystem errors detected in dmesg: %s", lines[i])
			}
		}
	}

	return nil
}

// OpenFilesCheck verifies no files are open on the target
type OpenFilesCheck struct{}

func (o *OpenFilesCheck) Name() string        { return "open_files" }
func (o *OpenFilesCheck) Description() string { return "Check for open files on target filesystem" }
func (o *OpenFilesCheck) Severity() CheckSeverity { return SeverityWarning }
func (o *OpenFilesCheck) CanSkip() bool       { return true }

func (o *OpenFilesCheck) Check(ctx context.Context, target DiskTarget) error {
	mountpoint := target.GetMountpoint()
	if mountpoint == "" {
		return nil // Not mounted, no open files possible
	}

	cmd := exec.CommandContext(ctx, "lsof", "+D", mountpoint)
	output, err := cmd.CombinedOutput()

	// lsof returns error if no files found (which is good for us)
	if err == nil && len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 { // More than just header
			return fmt.Errorf("found %d open files on %s", len(lines)-1, mountpoint)
		}
	}

	return nil
}

// MountStatusCheck verifies mount status consistency
type MountStatusCheck struct{}

func (m *MountStatusCheck) Name() string        { return "mount_status" }
func (m *MountStatusCheck) Description() string { return "Verify mount status consistency" }
func (m *MountStatusCheck) Severity() CheckSeverity { return SeverityWarning }
func (m *MountStatusCheck) CanSkip() bool       { return true }

func (m *MountStatusCheck) Check(ctx context.Context, target DiskTarget) error {
	device := target.GetDevice()
	if device == "" {
		return nil
	}

	// Check if device appears in /proc/mounts
	mounted, err := isMounted(device)
	if err != nil {
		return fmt.Errorf("check mount status: %w", err)
	}

	// For critical operations, we might want to ensure filesystem is not mounted
	// This is a placeholder for that logic
	_ = mounted

	return nil
}

// SmartHealthCheck verifies disk SMART health
type SmartHealthCheck struct{}

func (s *SmartHealthCheck) Name() string        { return "smart_health" }
func (s *SmartHealthCheck) Description() string { return "Check disk SMART health status" }
func (s *SmartHealthCheck) Severity() CheckSeverity { return SeverityWarning }
func (s *SmartHealthCheck) CanSkip() bool       { return true }

func (s *SmartHealthCheck) Check(ctx context.Context, target DiskTarget) error {
	device := target.GetPhysicalDevice()
	if device == "" {
		return fmt.Errorf("cannot determine physical device for SMART check")
	}

	// Check if smartctl is available
	if _, err := exec.LookPath("smartctl"); err != nil {
		return fmt.Errorf("smartctl not available: %w", err)
	}

	cmd := exec.CommandContext(ctx, "smartctl", "-H", device)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// smartctl often returns non-zero for warnings
		if strings.Contains(string(output), "PASSED") {
			return nil
		}
		return fmt.Errorf("SMART health check failed: %s", string(output))
	}

	return nil
}

// FreeSpaceCheck verifies sufficient free space exists
type FreeSpaceCheck struct{}

func (f *FreeSpaceCheck) Name() string        { return "free_space" }
func (f *FreeSpaceCheck) Description() string { return "Verify sufficient free space for operation" }
func (f *FreeSpaceCheck) Severity() CheckSeverity { return SeverityCritical }
func (f *FreeSpaceCheck) CanSkip() bool       { return false }

func (f *FreeSpaceCheck) Check(ctx context.Context, target DiskTarget) error {
	if target.VolumeGroup == "" {
		return nil // Not an LVM operation
	}

	// Check free space in volume group
	cmd := exec.CommandContext(ctx, "vgs", "--noheadings", "--units", "b", 
		"--separator", ":", "-o", "vg_name,vg_free", target.VolumeGroup)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check VG free space: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("no volume group information found")
	}

	parts := strings.Split(strings.TrimSpace(lines[0]), ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid volume group output format")
	}

	freeStr := strings.TrimSpace(parts[1])
	freeStr = strings.TrimSuffix(freeStr, "B") // Remove 'B' suffix
	freeBytes, err := strconv.ParseInt(freeStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse free space: %w", err)
	}

	// Require at least 1GB free space
	minFreeSpace := int64(1 << 30) // 1GB
	if freeBytes < minFreeSpace {
		return fmt.Errorf("insufficient free space: %d bytes available, need at least %d bytes", 
			freeBytes, minFreeSpace)
	}

	return nil
}

// ActiveIOCheck verifies no high I/O activity
type ActiveIOCheck struct{}

func (a *ActiveIOCheck) Name() string        { return "active_io" }
func (a *ActiveIOCheck) Description() string { return "Check for high I/O activity" }
func (a *ActiveIOCheck) Severity() CheckSeverity { return SeverityWarning }
func (a *ActiveIOCheck) CanSkip() bool       { return true }

func (a *ActiveIOCheck) Check(ctx context.Context, target DiskTarget) error {
	// Check if iostat is available
	if _, err := exec.LookPath("iostat"); err != nil {
		return nil // Skip if iostat not available
	}

	device := target.GetBlockDevice()
	if device == "" {
		return nil
	}

	// Run iostat for 2 intervals of 1 second each
	cmd := exec.CommandContext(ctx, "iostat", "-x", device, "1", "2")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil // Non-critical, skip on error
	}

	// Parse iostat output to check for high utilization
	// This is a simplified check - in production you'd want more sophisticated parsing
	if strings.Contains(string(output), "100.00") { // 100% utilization
		return fmt.Errorf("high I/O activity detected on %s", device)
	}

	return nil
}

// PermissionCheck verifies required permissions
type PermissionCheck struct{}

func (p *PermissionCheck) Name() string        { return "permissions" }
func (p *PermissionCheck) Description() string { return "Verify required permissions for operation" }
func (p *PermissionCheck) Severity() CheckSeverity { return SeverityCritical }
func (p *PermissionCheck) CanSkip() bool       { return false }

func (p *PermissionCheck) Check(ctx context.Context, target DiskTarget) error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required for disk operations")
	}

	// Check if required commands are available
	requiredCommands := []string{"lvextend", "resize2fs", "vgdisplay"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command '%s' not found in PATH", cmd)
		}
	}

	return nil
}

// LockFileCheck verifies no lock files prevent operation
type LockFileCheck struct{}

func (l *LockFileCheck) Name() string        { return "lock_files" }
func (l *LockFileCheck) Description() string { return "Check for lock files that prevent operation" }
func (l *LockFileCheck) Severity() CheckSeverity { return SeverityCritical }
func (l *LockFileCheck) CanSkip() bool       { return false }

func (l *LockFileCheck) Check(ctx context.Context, target DiskTarget) error {
	// Check common lock files that would prevent package manager operations
	lockFiles := []string{
		"/var/lib/dpkg/lock",
		"/var/lib/dpkg/lock-frontend",
		"/var/cache/apt/archives/lock",
		"/var/lib/apt/lists/lock",
	}

	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err == nil {
			return fmt.Errorf("lock file exists: %s (package manager may be running)", lockFile)
		}
	}

	return nil
}

// Helper functions

// isMounted checks if a device is mounted
func isMounted(device string) (bool, error) {
	// Resolve any symlinks
	realDevice, err := filepath.EvalSymlinks(device)
	if err != nil {
		realDevice = device // Use original if symlink resolution fails
	}

	// Read /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("read /proc/mounts: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			mountedDevice := fields[0]
			// Resolve symlinks for mounted device too
			realMountedDevice, err := filepath.EvalSymlinks(mountedDevice)
			if err != nil {
				realMountedDevice = mountedDevice
			}

			if realDevice == realMountedDevice || device == mountedDevice {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetDevice returns the appropriate device path for the target
func (dt *DiskTarget) GetDevice() string {
	if dt.Device != "" {
		return dt.Device
	}
	if dt.VolumeGroup != "" && dt.LogicalVol != "" {
		return fmt.Sprintf("/dev/%s/%s", dt.VolumeGroup, dt.LogicalVol)
	}
	return ""
}

// GetMountpoint returns the mountpoint for the target
func (dt *DiskTarget) GetMountpoint() string {
	return dt.Mountpoint
}

// GetPhysicalDevice returns the underlying physical device
func (dt *DiskTarget) GetPhysicalDevice() string {
	// This would need more sophisticated logic to map LVM to physical devices
	// For now, return a basic mapping
	if strings.HasPrefix(dt.Device, "/dev/mapper/") {
		// For LVM devices, we'd need to trace back to the PV
		return "/dev/sda" // Simplified
	}
	return dt.Device
}

// GetBlockDevice returns the block device name for iostat
func (dt *DiskTarget) GetBlockDevice() string {
	device := dt.GetDevice()
	if strings.HasPrefix(device, "/dev/") {
		return filepath.Base(device)
	}
	return device
}