package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// Assess performs comprehensive pre-flight checks before disk resize
func Assess(ctx context.Context, vmName string, change *SizeChange) (*Assessment, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Assessing VM for disk resize", zap.String("vm", vmName))

	a := &Assessment{
		VMName:          vmName,
		ChangeBytes:     change.Bytes,
		Risks:           []Risk{},
		RequiredActions: []string{},
	}

	// Connect to libvirt
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	// Get domain
	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil, fmt.Errorf("VM not found: %w", err)
	}
	defer domain.Free()

	// Check VM state
	if err := a.checkVMState(ctx, domain); err != nil {
		return nil, err
	}

	// Get disk information
	if err := a.getDiskInfo(ctx, domain); err != nil {
		return nil, err
	}

	// Calculate target size
	targetSize, err := CalculateTargetSize(a.CurrentSizeBytes, change)
	if err != nil {
		return nil, err
	}
	a.RequestedSizeBytes = targetSize

	// Check for snapshots
	a.checkSnapshots(ctx, domain)

	// Check guest agent
	a.checkGuestAgent(ctx, domain)

	// Check host resources
	if err := a.checkHostResources(ctx); err != nil {
		return nil, err
	}

	// Check for existing backups
	a.checkBackups(ctx)

	// Perform safety assessment
	a.assessSafety(ctx)

	logger.Info("Assessment complete",
		zap.String("vm", vmName),
		zap.Bool("safe_to_resize", a.SafeToResize),
		zap.Int("risks", len(a.Risks)))

	return a, nil
}

func (a *Assessment) checkVMState(ctx context.Context, domain *libvirt.Domain) error {
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	switch state {
	case libvirt.DOMAIN_RUNNING:
		a.State = "running"
	case libvirt.DOMAIN_SHUTOFF:
		a.State = "shut off"
	case libvirt.DOMAIN_PAUSED:
		a.State = "paused"
	case libvirt.DOMAIN_SHUTDOWN:
		a.State = "shutting down"
	default:
		a.State = "unknown"
	}

	return nil
}

func (a *Assessment) getDiskInfo(ctx context.Context, domain *libvirt.Domain) error {
	logger := otelzap.Ctx(ctx)

	// Get XML to find disk path
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("failed to get VM XML: %w", err)
	}

	// Parse disk path from XML (simplified - in production use proper XML parsing)
	// Look for <disk type='file'> ... <source file='/path/to/disk.qcow2'/>
	diskPathStart := strings.Index(xmlDesc, "<source file='")
	if diskPathStart == -1 {
		diskPathStart = strings.Index(xmlDesc, `<source file="`)
	}
	if diskPathStart == -1 {
		return fmt.Errorf("could not find disk path in VM XML")
	}

	diskPathStart += len("<source file='")
	if strings.Contains(xmlDesc[diskPathStart-len("<source file='"):diskPathStart], `"`) {
		diskPathStart = strings.Index(xmlDesc, `<source file="`) + len(`<source file="`)
	}

	diskPathEnd := strings.IndexAny(xmlDesc[diskPathStart:], "'\"")
	if diskPathEnd == -1 {
		return fmt.Errorf("malformed disk path in VM XML")
	}

	a.DiskPath = xmlDesc[diskPathStart : diskPathStart+diskPathEnd]
	logger.Debug("Found disk path", zap.String("path", a.DiskPath))

	// Get disk info using qemu-img
	cmd := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", a.DiskPath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get disk info: %w", err)
	}

	var diskInfo struct {
		Format      string `json:"format"`
		VirtualSize int64  `json:"virtual-size"`
		ActualSize  int64  `json:"actual-size"`
	}

	if err := json.Unmarshal(output, &diskInfo); err != nil {
		return fmt.Errorf("failed to parse disk info: %w", err)
	}

	a.Format = diskInfo.Format
	a.CurrentSizeBytes = diskInfo.VirtualSize

	logger.Debug("Disk information",
		zap.String("format", a.Format),
		zap.String("size", FormatBytes(a.CurrentSizeBytes)))

	return nil
}

func (a *Assessment) checkSnapshots(ctx context.Context, domain *libvirt.Domain) {
	logger := otelzap.Ctx(ctx)

	// List snapshots
	snapshots, err := domain.ListAllSnapshots(0)
	if err != nil {
		logger.Warn("Failed to list snapshots", zap.Error(err))
		return
	}

	a.SnapshotCount = len(snapshots)
	a.HasSnapshots = a.SnapshotCount > 0

	// Free snapshot handles
	for _, snap := range snapshots {
		snap.Free()
	}

	if a.HasSnapshots {
		logger.Debug("VM has snapshots", zap.Int("count", a.SnapshotCount))
	}
}

func (a *Assessment) checkGuestAgent(ctx context.Context, domain *libvirt.Domain) {
	logger := otelzap.Ctx(ctx)

	// Only works on running VMs
	if a.State != "running" {
		logger.Debug("VM not running, cannot check guest agent")
		return
	}

	// Try to ping guest agent
	_, err := domain.QemuAgentCommand(
		`{"execute":"guest-ping"}`,
		libvirt.DomainQemuAgentCommandTimeout(5),
		0,
	)

	a.HasGuestAgent = (err == nil)

	if a.HasGuestAgent {
		logger.Debug("Guest agent is responsive")

		// Try to get OS info
		result, err := domain.QemuAgentCommand(
			`{"execute":"guest-get-osinfo"}`,
			libvirt.DomainQemuAgentCommandTimeout(5),
			0,
		)

		if err == nil {
			var osInfo struct {
				Return struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"return"`
			}

			if err := json.Unmarshal([]byte(result), &osInfo); err == nil {
				a.GuestOS = strings.ToLower(osInfo.Return.Name)
				logger.Debug("Detected guest OS", zap.String("os", a.GuestOS))
			}
		}
	} else {
		logger.Debug("Guest agent not available")
	}
}

func (a *Assessment) checkHostResources(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Get filesystem stats for disk location
	diskDir := filepath.Dir(a.DiskPath)

	var stat syscall.Statfs_t
	if err := syscall.Statfs(diskDir, &stat); err != nil {
		return fmt.Errorf("failed to stat filesystem: %w", err)
	}

	// Available space in bytes
	a.HostFreeSpaceBytes = int64(stat.Bavail) * int64(stat.Bsize)

	logger.Debug("Host filesystem space",
		zap.String("path", diskDir),
		zap.String("free", FormatBytes(a.HostFreeSpaceBytes)))

	return nil
}

func (a *Assessment) checkBackups(ctx context.Context) {
	logger := otelzap.Ctx(ctx)

	// Check common backup locations
	backupDirs := []string{
		"/var/lib/eos/backups/kvm",
		"/backups",
		fmt.Sprintf("/var/lib/libvirt/images/backups"),
	}

	for _, dir := range backupDirs {
		pattern := filepath.Join(dir, fmt.Sprintf("%s*.qcow2", a.VMName))
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		if len(matches) > 0 {
			// Found backups, check the most recent
			var newestPath string
			var newestTime time.Time

			for _, match := range matches {
				info, err := os.Stat(match)
				if err != nil {
					continue
				}

				if info.ModTime().After(newestTime) {
					newestTime = info.ModTime()
					newestPath = match
				}
			}

			if newestPath != "" {
				a.BackupExists = true
				a.BackupPath = newestPath
				a.BackupAge = time.Since(newestTime)

				logger.Debug("Found backup",
					zap.String("path", newestPath),
					zap.Duration("age", a.BackupAge))
				return
			}
		}
	}

	logger.Debug("No backups found")
}

func (a *Assessment) assessSafety(ctx context.Context) {
	logger := otelzap.Ctx(ctx)

	a.SafeToResize = true

	// Critical risk: Shrinking operations
	if a.ChangeBytes < 0 {
		a.Risks = append(a.Risks, Risk{
			Level:       RiskLevelHigh,
			Description: "Shrinking disk can cause data loss if not done carefully",
			Mitigation:  "Ensure guest filesystem is shrunk first, or use --force flag",
		})
		a.SafeToResize = false
	}

	// High risk: VM running without guest agent
	if a.State == "running" && !a.HasGuestAgent {
		a.Risks = append(a.Risks, Risk{
			Level:       RiskLevelHigh,
			Description: "VM is running without guest agent - cannot automate guest operations",
			Mitigation:  "Shut down VM first, or install qemu-guest-agent in guest OS",
		})
		a.SafeToResize = false
	}

	// High risk: Snapshots present
	if a.HasSnapshots {
		a.Risks = append(a.Risks, Risk{
			Level:       RiskLevelMedium,
			Description: fmt.Sprintf("VM has %d snapshot(s) which complicate resize", a.SnapshotCount),
			Mitigation:  "Consider consolidating snapshots first",
		})
	}

	// Medium risk: Insufficient host space
	requiredSpace := CalculateRequiredSpace(a.CurrentSizeBytes, a.RequestedSizeBytes)
	if requiredSpace > a.HostFreeSpaceBytes {
		a.Risks = append(a.Risks, Risk{
			Level: RiskLevelHigh,
			Description: fmt.Sprintf("Insufficient host disk space (need %s, have %s)",
				FormatBytes(requiredSpace), FormatBytes(a.HostFreeSpaceBytes)),
			Mitigation: "Free up disk space on host before proceeding",
		})
		a.SafeToResize = false
	}

	// Medium risk: No recent backup
	if !a.BackupExists || a.BackupAge > 24*time.Hour {
		a.Risks = append(a.Risks, Risk{
			Level:       RiskLevelMedium,
			Description: "No recent backup found (or backup older than 24 hours)",
			Mitigation:  "Create a fresh backup before proceeding",
		})
		a.RequiredActions = append(a.RequiredActions, "Create backup before resize")
	}

	// Low risk: Unknown format
	if a.Format != "qcow2" && a.Format != "raw" {
		a.Risks = append(a.Risks, Risk{
			Level:       RiskLevelLow,
			Description: fmt.Sprintf("Disk format '%s' may not support online resize", a.Format),
			Mitigation:  "Verify format compatibility before proceeding",
		})
	}

	logger.Info("Safety assessment complete",
		zap.Bool("safe", a.SafeToResize),
		zap.Int("high_risks", countRisks(a.Risks, RiskLevelHigh)),
		zap.Int("medium_risks", countRisks(a.Risks, RiskLevelMedium)),
		zap.Int("low_risks", countRisks(a.Risks, RiskLevelLow)))
}

func countRisks(risks []Risk, level RiskLevel) int {
	count := 0
	for _, r := range risks {
		if r.Level == level {
			count++
		}
	}
	return count
}
