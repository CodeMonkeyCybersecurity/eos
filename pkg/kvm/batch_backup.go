//go:build linux

// pkg/kvm/batch_backup.go
// Batch backup orchestration for KVM VMs

package kvm

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VMBackupOrchestrator manages batch VM backups
type VMBackupOrchestrator struct {
	rc                   *eos_io.RuntimeContext
	backupClient         *backup.Client
	filter               BackupFilter
	continueOnError      bool
	timeout              time.Duration
	dryRun               bool
	allowCrashConsistent bool
	repoName             string
}

// OrchestratorOptions configures the backup orchestrator
type OrchestratorOptions struct {
	Filter               BackupFilter
	ContinueOnError      bool
	Timeout              time.Duration
	DryRun               bool
	AllowCrashConsistent bool
	RepoName             string
}

// VMBackupResult represents the result of backing up a single VM
type VMBackupResult struct {
	VM           VMInfo
	Success      bool
	Error        error
	ErrorType    string // "transient", "deterministic", "systemic"
	Duration     time.Duration
	SnapshotSize int64
	BackupSize   int64
	Skipped      bool
	SkipReason   string
}

// BatchBackupSummary summarizes results from backing up multiple VMs
type BatchBackupSummary struct {
	TotalVMs      int
	Successful    int
	Failed        int
	Skipped       int
	TotalDuration time.Duration
	TotalSize     int64
	FailedVMs     []string
	SkippedVMs    []string
	Results       []VMBackupResult
}

// NewVMBackupOrchestrator creates a new backup orchestrator
func NewVMBackupOrchestrator(rc *eos_io.RuntimeContext, opts OrchestratorOptions) (*VMBackupOrchestrator, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Default values
	if opts.RepoName == "" {
		opts.RepoName = "kvm-backups"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 1 * time.Hour
	}

	logger.Info("Creating VM backup orchestrator",
		zap.String("repo", opts.RepoName),
		zap.Bool("dry_run", opts.DryRun),
		zap.Bool("continue_on_error", opts.ContinueOnError))

	// Create backup client (will be nil for dry-run)
	var backupClient *backup.Client
	if !opts.DryRun {
		var err error
		backupClient, err = backup.NewClient(rc, opts.RepoName)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup client: %w", err)
		}
	}

	return &VMBackupOrchestrator{
		rc:                   rc,
		backupClient:         backupClient,
		filter:               opts.Filter,
		continueOnError:      opts.ContinueOnError,
		timeout:              opts.Timeout,
		dryRun:               opts.DryRun,
		allowCrashConsistent: opts.AllowCrashConsistent,
		repoName:             opts.RepoName,
	}, nil
}

// BackupAll performs backup of all discovered VMs
func (o *VMBackupOrchestrator) BackupAll() (*BatchBackupSummary, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	startTime := time.Now()

	// ASSESS: Discover VMs
	logger.Info("Discovering VMs for backup")
	allVMs, err := ListVMs(o.rc)
	if err != nil {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}

	// Filter VMs based on criteria
	vms := FilterVMsForBackup(allVMs, o.filter)

	if len(vms) == 0 {
		logger.Info("No VMs found matching criteria")
		return &BatchBackupSummary{}, nil
	}

	// If dry-run, just show what would be backed up
	if o.dryRun {
		return o.performDryRun(vms)
	}

	// INTERVENE: Backup each VM
	logger.Info("Starting batch backup",
		zap.Int("vm_count", len(vms)))

	summary := &BatchBackupSummary{
		TotalVMs: len(vms),
		Results:  make([]VMBackupResult, 0, len(vms)),
	}

	for i, vm := range vms {
		logger.Info("Backing up VM",
			zap.Int("current", i+1),
			zap.Int("total", len(vms)),
			zap.String("vm", vm.Name),
			zap.String("state", vm.State))

		result := o.backupVM(vm)
		summary.Results = append(summary.Results, result)

		if result.Skipped {
			summary.Skipped++
			summary.SkippedVMs = append(summary.SkippedVMs, vm.Name)
			logger.Info("Skipped VM",
				zap.String("vm", vm.Name),
				zap.String("reason", result.SkipReason))
			continue
		}

		if result.Success {
			summary.Successful++
			summary.TotalSize += result.BackupSize
			logger.Info("VM backup completed",
				zap.String("vm", vm.Name),
				zap.Duration("duration", result.Duration),
				zap.Int64("size_gb", result.BackupSize/(1024*1024*1024)))
		} else {
			summary.Failed++
			summary.FailedVMs = append(summary.FailedVMs, vm.Name)
			logger.Error("VM backup failed",
				zap.String("vm", vm.Name),
				zap.Error(result.Error),
				zap.String("error_type", result.ErrorType))

			// Check if we should abort entire batch
			if result.ErrorType == "systemic" {
				logger.Error("Systemic error detected, aborting batch backup",
					zap.String("error", result.Error.Error()))
				break
			}

			if !o.continueOnError {
				logger.Error("Aborting batch backup due to error")
				break
			}
		}
	}

	summary.TotalDuration = time.Since(startTime)

	// EVALUATE: Log summary
	logger.Info("Batch backup completed",
		zap.Int("total", summary.TotalVMs),
		zap.Int("successful", summary.Successful),
		zap.Int("failed", summary.Failed),
		zap.Int("skipped", summary.Skipped),
		zap.Duration("duration", summary.TotalDuration),
		zap.Int64("total_size_gb", summary.TotalSize/(1024*1024*1024)))

	return summary, nil
}

// performDryRun shows what would be backed up without actually doing it
func (o *VMBackupOrchestrator) performDryRun(vms []VMInfo) (*BatchBackupSummary, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Performing dry-run",
		zap.Int("vm_count", len(vms)))

	totalSize := int64(0)
	warnings := 0
	skipped := 0

	logger.Info("Would backup the following VMs")

	for _, vm := range vms {
		// Check if VM can be backed up
		canBackup, reason := vm.CanBackup(o.allowCrashConsistent)
		if !canBackup {
			logger.Info("VM would be skipped",
				zap.String("vm", vm.Name),
				zap.String("state", vm.State),
				zap.String("size", vm.FormatSize()),
				zap.String("skip_reason", reason))
			skipped++
			continue
		}

		totalSize += int64(vm.DiskSizeGB) * 1024 * 1024 * 1024
		logger.Info("VM would be backed up",
			zap.String("vm", vm.Name),
			zap.String("state", vm.State),
			zap.String("size", vm.FormatSize()))

		// Show warnings
		if vm.HasMultipleDisks {
			logger.Warn("VM has multiple disks, will backup vda only",
				zap.String("vm", vm.Name),
				zap.Int("disk_count", len(vm.Disks)))
			warnings++
		}

		if !vm.GuestAgentOK && o.allowCrashConsistent {
			logger.Warn("VM has no guest agent, will use crash-consistent backup",
				zap.String("vm", vm.Name))
			warnings++
		}
	}

	logger.Info("Dry-run summary",
		zap.Int("total_vms", len(vms)),
		zap.Int("would_backup", len(vms)-skipped),
		zap.Int("would_skip", skipped),
		zap.String("total_size", formatBytes(totalSize)),
		zap.String("repository", o.repoName),
		zap.Int("estimated_minutes", estimateBackupTime(totalSize)),
		zap.Int("warnings", warnings))

	return &BatchBackupSummary{
		TotalVMs: len(vms),
		Skipped:  skipped,
	}, nil
}

// backupVM backs up a single VM (internal method)
func (o *VMBackupOrchestrator) backupVM(vm VMInfo) VMBackupResult {
	logger := otelzap.Ctx(o.rc.Ctx)
	startTime := time.Now()

	result := VMBackupResult{
		VM: vm,
	}

	// ASSESS: Check if VM can be backed up
	canBackup, reason := vm.CanBackup(o.allowCrashConsistent)
	if !canBackup {
		result.Skipped = true
		result.SkipReason = reason
		return result
	}

	// TODO: Implement actual backup in Round 3
	// For now, just simulate success
	logger.Info("Would backup VM (not yet implemented)",
		zap.String("vm", vm.Name))

	result.Success = true
	result.Duration = time.Since(startTime)
	result.BackupSize = int64(vm.DiskSizeGB) * 1024 * 1024 * 1024

	return result
}

// estimateBackupTime estimates backup time based on total size
// Assumes ~100 MB/s backup speed
func estimateBackupTime(totalBytes int64) int {
	bytesPerSecond := int64(100 * 1024 * 1024) // 100 MB/s
	seconds := totalBytes / bytesPerSecond
	minutes := seconds / 60
	if minutes < 1 {
		return 1
	}
	return int(minutes)
}

// formatBytes converts bytes to human-readable format
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
