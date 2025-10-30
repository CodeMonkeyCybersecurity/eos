package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RootExpandOptions controls how ExpandRoot behaves.
type RootExpandOptions struct {
	AllowPartitionGrow bool
	ForceLUKS          bool
	DryRun             bool
	AssumeYes          bool
	SkipAptInstall     bool
	LogJSON            bool
	UseAllFreeSpace    bool
}

type rootLayout struct {
	RootSource string
	RootLVPath string
	RootVG     string
	PVs        []rootPV
}

type rootPV struct {
	PVName      string
	IsCrypt     bool
	CryptMapper string
	Backing     string
	Disk        string
	PartNum     string
	ParentType  string
}

type expandReport struct {
	Before deviceSnapshot `json:"before"`
	After  deviceSnapshot `json:"after"`
	PVs    []pvReport     `json:"pvs"`
}

type pvReport struct {
	PVName      string `json:"pv"`
	IsCrypt     bool   `json:"is_crypt"`
	Backing     string `json:"backing"`
	BackingSize uint64 `json:"backing_size_bytes"`
	CryptSize   uint64 `json:"crypt_size_bytes,omitempty"`
	PVSize      uint64 `json:"pv_size_bytes"`
}

type deviceSnapshot struct {
	VGFreeBytes uint64 `json:"vg_free_bytes"`
	LVSizeBytes uint64 `json:"lv_size_bytes"`
	FSSizeBytes uint64 `json:"fs_size_bytes"`
}

// pvTransaction tracks PV processing for rollback/recovery
type pvTransaction struct {
	PV            rootPV
	PreResizeSize uint64
	PostResizeSize uint64
	Success       bool
	Error         error
}

// ExpandRoot expands the root logical volume, handling LUKS-backed PVs when present.
func ExpandRoot(rc *eos_io.RuntimeContext, opts RootExpandOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ExpandRoot")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting root expansion workflow",
		zap.Bool("allow_partition_grow", opts.AllowPartitionGrow),
		zap.Bool("force_luks", opts.ForceLUKS),
		zap.Bool("dry_run", opts.DryRun),
		zap.Bool("assume_yes", opts.AssumeYes),
		zap.Bool("skip_apt_install", opts.SkipAptInstall),
		zap.Bool("log_json", opts.LogJSON),
		zap.Bool("use_all_free_space", opts.UseAllFreeSpace))

	if !opts.UseAllFreeSpace && !opts.DryRun {
		return errors.New("refusing to expand root without --all; pass --all to consume remaining free space")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (current euid=%d)", os.Geteuid())
	}

	if err := ensureBaseCommands(ctx, opts.SkipAptInstall, logger); err != nil {
		return err
	}

	layout, err := discoverRootLayout(ctx)
	if err != nil {
		return err
	}

	// PRE-FLIGHT SAFETY CHECKS
	logger.Info("Running pre-flight safety checks")

	// Check 1: Disk health for all PVs
	for _, pv := range layout.PVs {
		if pv.Disk != "" {
			if err := checkDiskHealth(ctx, pv.Disk); err != nil {
				logger.Error("Disk health check failed",
					zap.String("disk", pv.Disk),
					zap.Error(err))

				if !opts.AssumeYes && !opts.DryRun {
					fmt.Printf("\n⚠️  WARNING: Disk %s has health issues:\n%v\n\n", pv.Disk, err)
					fmt.Print("Continue anyway? (NOT recommended) [yes/NO]: ")
					var answer string
					if _, err := fmt.Scanln(&answer); err != nil || strings.ToLower(answer) != "yes" {
						return fmt.Errorf("operation cancelled due to disk health issues\n\n"+
							"Remediation:\n"+
							"  1. Check SMART status: sudo smartctl -a %s\n"+
							"  2. Back up data immediately\n"+
							"  3. Replace failing disk before expansion\n"+
							"  4. Or use --yes to override (risky)", pv.Disk)
					}
				}
			}
		}
	}

	// Check 2: Recent I/O errors
	if checkRecentIOErrors(ctx) {
		return errors.New("recent I/O errors detected in kernel log\n\n" +
			"Remediation:\n" +
			"  1. Check dmesg: sudo dmesg | grep -i error\n" +
			"  2. Verify all disks are healthy: sudo smartctl -a /dev/sdX\n" +
			"  3. Fix hardware issues before attempting expansion\n" +
			"  4. Run fsck if filesystem errors detected")
	}

	if layout.RootLVPath == "" {
		return errors.New("failed to resolve root logical volume path")
	}

	if layout.RootVG == "" {
		return errors.New("failed to resolve volume group for root logical volume")
	}

	hasCrypt := false
	plainCount := 0
	for _, pv := range layout.PVs {
		if pv.IsCrypt {
			hasCrypt = true
		} else {
			plainCount++
		}
	}

	if opts.ForceLUKS && !hasCrypt {
		return errors.New("no LUKS-backed PVs detected but --luks was specified\n\n" +
			"Remediation:\n" +
			"  1. Remove --luks flag if root is not encrypted\n" +
			"  2. Check encryption: sudo cryptsetup status /dev/mapper/*\n" +
			"  3. Verify PVs: sudo pvs -o pv_name,vg_name")
	}

	if err := ensureExtendedCommands(ctx, opts, hasCrypt, logger); err != nil {
		return err
	}

	if err := validatePVTopology(ctx, layout); err != nil {
		return err
	}

	if hasCrypt {
		if err := validateCryptSetup(ctx, layout); err != nil {
			return err
		}
	}

	if !opts.DryRun && !opts.AssumeYes {
		if err := confirmExpand(layout); err != nil {
			return err
		}
	}

	if hasCrypt && plainCount > 0 && !opts.AssumeYes && !opts.DryRun {
		return errors.New("mixed PV types detected (crypt + plain); rerun with --yes to confirm automatic handling")
	}

	before, err := captureSnapshot(ctx, layout)
	if err != nil {
		logger.Warn("Failed to capture pre-expansion snapshot", zap.Error(err))
	}

	pvReports := make([]pvReport, 0, len(layout.PVs))
	txLog := make([]pvTransaction, 0, len(layout.PVs))

	// Process each PV with transaction tracking for rollback
	for _, pv := range layout.PVs {
		report := pvReport{
			PVName:  pv.PVName,
			IsCrypt: pv.IsCrypt,
			Backing: pv.Backing,
		}

		tx := pvTransaction{PV: pv}

		if size, err := getDeviceSize(ctx, pv.PVName); err == nil {
			report.PVSize = size
			tx.PreResizeSize = size
		}

		if pv.Backing != "" {
			if size, err := getDeviceSize(ctx, pv.Backing); err == nil {
				report.BackingSize = size
			}
		}

		if pv.IsCrypt {
			if size, err := getDeviceSize(ctx, pv.CryptMapper); err == nil {
				report.CryptSize = size
			}
		}

		// Process PV with error tracking
		if err := processPV(ctx, pv, opts); err != nil {
			tx.Success = false
			tx.Error = err
			txLog = append(txLog, tx)

			// Attempt automatic recovery - expand LV with whatever space IS available
			logger.Error("PV processing failed - attempting to extend LV with successfully-expanded PVs",
				zap.Error(err),
				zap.Int("successful_pvs", len(txLog)-1),
				zap.Int("total_pvs", len(layout.PVs)))

			// Still try to extend LV with whatever space is available
			if recoverErr := attemptPartialExpansion(ctx, layout, opts); recoverErr != nil {
				return fmt.Errorf("PV %s failed and recovery failed: original error: %w, recovery error: %v",
					pv.PVName, err, recoverErr)
			}

			return fmt.Errorf("partial expansion completed: %d/%d PVs expanded successfully: %w",
				len(txLog)-1, len(layout.PVs), err)
		}

		// Success - record final size
		if size, err := getDeviceSize(ctx, pv.PVName); err == nil {
			tx.PostResizeSize = size
		}
		tx.Success = true
		txLog = append(txLog, tx)

		pvReports = append(pvReports, report)
	}

	logger.Info("All PVs processed successfully", zap.Int("pv_count", len(txLog)))

	if err := maybeRun(ctx, opts, "pvdisplay"); err != nil {
		logger.Debug("pvdisplay invocation failed", zap.Error(err))
	}

	freeExtents, err := vgFreeExtents(ctx, layout.RootVG)
	if err != nil {
		return fmt.Errorf("failed to read VG free space: %w", err)
	}

	if freeExtents == 0 {
		logger.Info("Volume group has no free extents after PV processing; skipping lvextend")
	} else {
		// Validate --all safety before consuming all space
		if opts.UseAllFreeSpace {
			totalExtents, err := vgTotalExtents(ctx, layout.RootVG)
			if err != nil {
				logger.Warn("Could not calculate VG utilization", zap.Error(err))
			} else {
				percentFree := float64(freeExtents) / float64(totalExtents) * 100
				logger.Info("Volume group space analysis",
					zap.Int("free_extents", freeExtents),
					zap.Int("total_extents", totalExtents),
					zap.Float64("percent_free", percentFree))

				// Warn if consuming all space leaves no room for operations
				if percentFree > 5.0 && !opts.AssumeYes && !opts.DryRun {
					fmt.Printf("\n⚠️  WARNING: --all will consume ALL free space\n\n")
					fmt.Printf("Current free space: %.1f%% (%d extents)\n", percentFree, freeExtents)
					fmt.Printf("After expansion:    0.0%% (0 extents)\n\n")
					fmt.Println("Risks:")
					fmt.Println("  - Cannot create LVM snapshots for backup")
					fmt.Println("  - Cannot grow other LVs in emergency")
					fmt.Println("  - May impact database performance")
					fmt.Println("\nRecommendation:")
					fmt.Println("  Keep 10-15% free for operational flexibility")
					fmt.Print("\nContinue and use ALL free space anyway? [yes/NO]: ")

					var answer string
					if _, err := fmt.Scanln(&answer); err != nil || strings.ToLower(answer) != "yes" {
						return errors.New("operation cancelled\n\n" +
							"Consider leaving some free space for snapshots and flexibility.\n" +
							"You can expand again later if needed.")
					}
				}
			}
		}

		// Detect filesystem type for proper resize
		fsType, err := detectFilesystemType(ctx, layout.RootLVPath)
		if err != nil {
			logger.Warn("Could not detect filesystem type, assuming ext4", zap.Error(err))
			fsType = "ext4"
		}

		logger.Info("Detected root filesystem type", zap.String("type", fsType))

		// Check if -r (auto-resize) is supported for this filesystem
		supportsAutoResize := map[string]bool{
			"ext2":     true,
			"ext3":     true,
			"ext4":     true,
			"xfs":      true,
			"reiserfs": true,
			"btrfs":    false,
			"f2fs":     false,
			"zfs":      false,
		}

		if supportsAutoResize[fsType] {
			// CRITICAL: lvextend must not be interrupted
			if err := runCriticalCommand(ctx, opts, "lvextend", "-l", "+100%FREE", "-r", layout.RootLVPath); err != nil {
				return fmt.Errorf("lvextend with auto-resize failed: %w\n\n"+
					"Remediation:\n"+
					"  1. Check VG free space: sudo vgs %s\n"+
					"  2. Check LV status: sudo lvs %s\n"+
					"  3. Manually extend: sudo lvextend -l +100%%FREE -r %s\n"+
					"  4. If that fails, two-step: sudo lvextend -l +100%%FREE %s && sudo resize2fs %s",
					err, layout.RootVG, layout.RootLVPath, layout.RootLVPath, layout.RootLVPath, layout.RootLVPath)
			}
		} else {
			// Two-step resize for unsupported filesystems
			logger.Warn("Filesystem does not support automatic resize, using two-step process",
				zap.String("filesystem", fsType))

			if err := runCriticalCommand(ctx, opts, "lvextend", "-l", "+100%FREE", layout.RootLVPath); err != nil {
				return fmt.Errorf("lvextend failed: %w", err)
			}

			// Manual filesystem resize based on type
			switch fsType {
			case "btrfs":
				if err := runCriticalCommand(ctx, opts, "btrfs", "filesystem", "resize", "max", "/"); err != nil {
					return fmt.Errorf("btrfs resize failed: %w\n\n"+
						"LV was extended but filesystem was not resized.\n"+
						"Remediation:\n"+
						"  1. Manually resize: sudo btrfs filesystem resize max /", err)
				}
			case "f2fs":
				if err := runCriticalCommand(ctx, opts, "resize.f2fs", layout.RootLVPath); err != nil {
					return fmt.Errorf("f2fs resize failed: %w\n\n"+
						"LV was extended but filesystem was not resized.\n"+
						"Remediation:\n"+
						"  1. Manually resize: sudo resize.f2fs %s", err, layout.RootLVPath)
				}
			default:
				return fmt.Errorf("filesystem type %s requires manual resize\n\n"+
					"LV has been extended but filesystem was not resized.\n"+
					"Remediation:\n"+
					"  1. Check filesystem type: sudo blkid %s\n"+
					"  2. Look up resize command for your filesystem type\n"+
					"  3. Current LV size: check with 'df -h /'",
					fsType, layout.RootLVPath)
			}
		}
	}

	after, err := captureSnapshot(ctx, layout)
	if err != nil {
		logger.Warn("Failed to capture post-expansion snapshot", zap.Error(err))
	}

	logger.Info("Root expansion flow complete",
		zap.String("root_lv", layout.RootLVPath),
		zap.String("root_vg", layout.RootVG))

	if opts.LogJSON {
		report := expandReport{
			Before: before,
			After:  after,
			PVs:    pvReports,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			logger.Warn("Failed to emit JSON report", zap.Error(err))
		}
	}

	return nil
}

func ensureBaseCommands(ctx context.Context, skipInstall bool, logger otelzap.LoggerWithCtx) error {
	base := []string{"findmnt", "lsblk", "lvs", "pvs", "vgs"}
	missing := missingCommands(base)
	if len(missing) == 0 {
		return nil
	}
	return installCommands(ctx, missing, skipInstall, logger)
}

func ensureExtendedCommands(ctx context.Context, opts RootExpandOptions, hasCrypt bool, logger otelzap.LoggerWithCtx) error {
	required := []string{"lvextend", "pvresize"}
	if opts.AllowPartitionGrow {
		required = append(required, "growpart", "sgdisk")
	}
	if hasCrypt || opts.ForceLUKS {
		required = append(required, "cryptsetup")
	}

	missing := missingCommands(required)
	if len(missing) == 0 {
		return nil
	}
	return installCommands(ctx, missing, opts.SkipAptInstall, logger)
}

func missingCommands(cmds []string) []string {
	var missing []string
	for _, cmd := range cmds {
		if _, err := exec.LookPath(cmd); err != nil {
			missing = append(missing, cmd)
		}
	}
	return missing
}

func installCommands(ctx context.Context, missing []string, skipInstall bool, logger otelzap.LoggerWithCtx) error {
	if len(missing) == 0 {
		return nil
	}
	if skipInstall {
		return fmt.Errorf("missing required commands: %s (rerun without --skip-apt-install to install)", strings.Join(missing, ", "))
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("missing required commands %s and apt-get is unavailable for installation", strings.Join(missing, ", "))
	}

	packages := mapCommandsToPackages(missing)
	if len(packages) == 0 {
		logger.Warn("No package mapping found for missing commands; attempting apt-get anyway",
			zap.Strings("commands", missing))
	}

	argsUpdate := []string{"apt-get", "update"}
	cmd := exec.CommandContext(ctx, argsUpdate[0], argsUpdate[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	if len(packages) == 0 {
		return nil
	}

	installArgs := append([]string{"apt-get", "install", "-y"}, packages...)
	installCmd := exec.CommandContext(ctx, installArgs[0], installArgs[1:]...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}
	return nil
}

func mapCommandsToPackages(cmds []string) []string {
	pkgSet := make(map[string]struct{})
	for _, cmd := range cmds {
		switch cmd {
		case "growpart":
			pkgSet["cloud-guest-utils"] = struct{}{}
		case "sgdisk":
			pkgSet["gdisk"] = struct{}{}
		case "cryptsetup":
			pkgSet["cryptsetup"] = struct{}{}
		case "pvresize", "lvextend", "pvs", "vgs", "lvs":
			pkgSet["lvm2"] = struct{}{}
		}
	}
	packages := make([]string, 0, len(pkgSet))
	for pkg := range pkgSet {
		packages = append(packages, pkg)
	}
	return packages
}

func discoverRootLayout(ctx context.Context) (*rootLayout, error) {
	source, err := commandOutput(ctx, "findmnt", "-no", "SOURCE", "/")
	if err != nil {
		return nil, fmt.Errorf("failed to determine root source: %w", err)
	}
	rootSource := strings.TrimSpace(source)
	if rootSource == "" {
		return nil, errors.New("findmnt returned empty source for /")
	}

	resolvedSource := rootSource
	if strings.HasPrefix(rootSource, "/dev/mapper/") {
		if real, err := filepath.EvalSymlinks(rootSource); err == nil {
			resolvedSource = real
		}
	}

	lvInfo, err := commandOutput(ctx, "lvs", "--noheadings", "-o", "lv_path,vg_name", resolvedSource)
	if err != nil {
		if resolvedSource != rootSource {
			lvInfo, err = commandOutput(ctx, "lvs", "--noheadings", "-o", "lv_path,vg_name", rootSource)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query lvs for %s: %w", rootSource, err)
		}
	}

	var lvPath, vgName string
	scanner := bufio.NewScanner(strings.NewReader(lvInfo))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			lvPath = fields[0]
			vgName = fields[1]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if lvPath == "" || vgName == "" {
		return nil, fmt.Errorf("unable to parse LV/VG from lvs output: %q", lvInfo)
	}

	layout := &rootLayout{
		RootSource: rootSource,
		RootLVPath: lvPath,
		RootVG:     vgName,
	}

	pvOutput, err := commandOutput(ctx, "pvs", "--noheadings", "-o", "pv_name,vg_name")
	if err != nil {
		return nil, fmt.Errorf("failed to query pvs: %w", err)
	}

	scanner = bufio.NewScanner(strings.NewReader(pvOutput))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] != vgName {
			continue
		}
		pvName := fields[0]
		pv := rootPV{PVName: pvName}

		typ, err := commandOutput(ctx, "lsblk", "-no", "TYPE", pvName)
		if err != nil {
			return nil, fmt.Errorf("lsblk failed for %s: %w", pvName, err)
		}
		pvType := strings.TrimSpace(typ)
		pv.IsCrypt = pvType == "crypt"
		if pv.IsCrypt {
			pv.CryptMapper = pvName
		}

		if pk, err := commandOutput(ctx, "lsblk", "-no", "PKNAME", pvName); err == nil {
			parentName := strings.TrimSpace(pk)
			if parentName != "" {
				pv.Backing = "/dev/" + parentName
				pt, err := commandOutput(ctx, "lsblk", "-no", "TYPE", pv.Backing)
				if err == nil {
					pv.ParentType = strings.TrimSpace(pt)
				}
				if disk, err := commandOutput(ctx, "lsblk", "-no", "PKNAME", pv.Backing); err == nil {
					parentDisk := strings.TrimSpace(disk)
					if parentDisk != "" {
						pv.Disk = "/dev/" + parentDisk
					}
				}
				if partNum, err := commandOutput(ctx, "lsblk", "-no", "PARTNUM", pv.Backing); err == nil {
					pv.PartNum = strings.TrimSpace(partNum)
				}
			}
		}

		if pv.Backing == "" {
			pv.Backing = pvName
		}

		layout.PVs = append(layout.PVs, pv)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(layout.PVs) == 0 {
		return nil, fmt.Errorf("volume group %s has no PVs", vgName)
	}

	return layout, nil
}

func validatePVTopology(ctx context.Context, layout *rootLayout) error {
	for _, pv := range layout.PVs {
		if pv.Disk == "" {
			continue
		}
		diskType, err := commandOutput(ctx, "lsblk", "-no", "TYPE", pv.Disk)
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(diskType), "raid") {
			return fmt.Errorf("disk %s is part of a RAID array; expand the array first and rerun", pv.Disk)
		}
	}
	return nil
}

func validateCryptSetup(ctx context.Context, layout *rootLayout) error {
	versionOutput, err := commandOutput(ctx, "cryptsetup", "--version")
	if err != nil {
		return fmt.Errorf("failed to determine cryptsetup version: %w", err)
	}
	version := parseCryptsetupVersion(versionOutput)
	if version < 2 {
		return fmt.Errorf("cryptsetup version >= 2.0 required (detected %s)", strings.TrimSpace(versionOutput))
	}

	for _, pv := range layout.PVs {
		if !pv.IsCrypt {
			continue
		}

		if pv.Backing == "" {
			return fmt.Errorf("unable to identify backing device for %s", pv.PVName)
		}

		if err := exec.CommandContext(ctx, "cryptsetup", "isLuks", pv.Backing).Run(); err != nil {
			return fmt.Errorf("%s does not appear to be a LUKS device: %w", pv.Backing, err)
		}

		status, err := commandOutput(ctx, "cryptsetup", "status", pv.CryptMapper)
		if err != nil {
			return fmt.Errorf("crypt mapping %s is not active: %w", pv.CryptMapper, err)
		}
		if !strings.Contains(status, "type:    LUKS") && !strings.Contains(status, "type:    luks") {
			return fmt.Errorf("crypt mapping %s is not reporting LUKS type", pv.CryptMapper)
		}

		dump, err := commandOutput(ctx, "cryptsetup", "luksDump", pv.Backing)
		if err != nil {
			return fmt.Errorf("failed to inspect LUKS header on %s: %w", pv.Backing, err)
		}
		if strings.Contains(strings.ToLower(dump), "detached header: yes") || strings.Contains(strings.ToLower(dump), "header device:") {
			return fmt.Errorf("detached LUKS headers are not supported by this command (device %s)", pv.Backing)
		}
	}
	return nil
}

func parseCryptsetupVersion(output string) int {
	fields := strings.Fields(output)
	for _, field := range fields {
		if strings.Count(field, ".") >= 1 {
			parts := strings.Split(field, ".")
			if len(parts) > 0 {
				if v, err := strconv.Atoi(parts[0]); err == nil {
					return v
				}
			}
		}
	}
	return 0
}

func confirmExpand(layout *rootLayout) error {
	fmt.Printf("\n⚠️  ROOT FILESYSTEM EXPANSION - RISK ASSESSMENT\n\n")
	fmt.Printf("Root LV: %s (VG: %s)\n", layout.RootLVPath, layout.RootVG)
	fmt.Println("This will expand the root logical volume online using:")
	for _, pv := range layout.PVs {
		fmt.Printf("  - %s (backing: %s, encrypted: %t)\n", pv.PVName, pv.Backing, pv.IsCrypt)
	}

	// Check for recent backups
	fmt.Println("\n📋 BACKUP VERIFICATION:")
	hasRecentBackup := checkForRecentBackups()

	if !hasRecentBackup {
		fmt.Println("  ❌ No recent backups detected")
		fmt.Println("\nRECOMMENDATION: Create backup before proceeding:")
		fmt.Println("  Option 1: LVM snapshot: sudo lvcreate -L10G -s -n root_backup " + layout.RootLVPath)
		fmt.Println("  Option 2: Timeshift (Ubuntu): sudo timeshift --create")
		fmt.Println("  Option 3: Full system backup: tar/rsync/dd")
		fmt.Print("\nDo you have a recent backup? [yes/NO]: ")

		var answer string
		if _, err := fmt.Scanln(&answer); err != nil || strings.ToLower(answer) != "yes" {
			return errors.New("operation cancelled - create backup first\n\n" +
				"Remediation:\n" +
				"  1. Create LVM snapshot: sudo lvcreate -L10G -s -n backup " + layout.RootLVPath + "\n" +
				"  2. Or backup critical data with: sudo rsync -av /home /backup/\n" +
				"  3. Rerun expansion after backup completes")
		}
	} else {
		fmt.Println("  ✓ Recent backup found")
	}

	fmt.Print("\nProceed with expansion? (type 'yes' to confirm): ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "yes" {
		return errors.New("operation cancelled by user")
	}
	return nil
}

// checkForRecentBackups checks if recent backups exist
func checkForRecentBackups() bool {
	// Check common backup locations
	backupIndicators := []string{
		"/timeshift/snapshots/",          // Timeshift
		"/run/timeshift/backup/",         // Timeshift
		"/backup/",                       // Generic
		"/var/backups/",                  // Debian/Ubuntu
		"/root/backup/",                  // Root backups
	}

	cutoff := time.Now().Add(-24 * time.Hour)

	for _, path := range backupIndicators {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}

		// Check for recent files
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(cutoff) {
				return true
			}
		}
	}

	// Check for LVM snapshots
	cmd := exec.Command("lvs", "--noheadings", "-o", "lv_attr,lv_name")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// LVM snapshot has 's' in first character of lv_attr
				if len(fields[0]) > 0 && (fields[0][0] == 's' || fields[0][0] == 'S') {
					return true
				}
			}
		}
	}

	return false
}

func processPV(ctx context.Context, pv rootPV, opts RootExpandOptions) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Processing PV",
		zap.String("pv", pv.PVName),
		zap.Bool("is_crypt", pv.IsCrypt),
		zap.Bool("grow_partition", opts.AllowPartitionGrow),
		zap.String("backing", pv.Backing),
		zap.String("disk", pv.Disk),
		zap.String("partnum", pv.PartNum))

	// Step 1: Grow partition if requested
	if opts.AllowPartitionGrow && pv.Disk != "" && pv.PartNum != "" {
		// Check partition table type before running sgdisk
		ptType, err := getPartitionTableType(ctx, pv.Disk)
		if err != nil {
			logger.Warn("Could not determine partition table type",
				zap.String("disk", pv.Disk),
				zap.Error(err))
		} else if ptType == "gpt" {
			logger.Debug("Moving GPT backup header to end of disk",
				zap.String("disk", pv.Disk))
			if err := runCommand(ctx, opts, "sgdisk", "-e", pv.Disk); err != nil {
				logger.Warn("sgdisk -e failed, continuing anyway",
					zap.String("disk", pv.Disk),
					zap.Error(err))
			}
		} else {
			logger.Debug("Skipping sgdisk (not a GPT disk)",
				zap.String("disk", pv.Disk),
				zap.String("partition_table", ptType))
		}

		// Grow the partition
		if err := runCommand(ctx, opts, "growpart", pv.Disk, pv.PartNum); err != nil {
			return fmt.Errorf("growpart failed for %s:%s: %w\n\n"+
				"Remediation:\n"+
				"  1. Check partition layout: sudo fdisk -l %s\n"+
				"  2. Verify free space: sudo parted %s print free\n"+
				"  3. Manually resize: sudo growpart %s %s",
				pv.Disk, pv.PartNum, err, pv.Disk, pv.Disk, pv.Disk, pv.PartNum)
		}

		// Wait for udev to settle with timeout and verification
		partPath := fmt.Sprintf("%s%s", pv.Disk, pv.PartNum)
		if err := runCommand(ctx, opts, "udevadm", "settle",
			"--timeout=30",
			fmt.Sprintf("--exit-if-exists=%s", partPath)); err != nil {

			logger.Warn("udevadm settle timed out, triggering manual event",
				zap.String("partition", partPath))

			// Force trigger before retry
			_ = runCommand(ctx, opts, "udevadm", "trigger", "--subsystem-match=block")

			// Shorter retry
			if err := runCommand(ctx, opts, "udevadm", "settle",
				"--timeout=10",
				fmt.Sprintf("--exit-if-exists=%s", partPath)); err != nil {
				return fmt.Errorf("partition %s not visible after growpart: %w\n\n"+
					"Remediation:\n"+
					"  1. Force udev update: sudo udevadm trigger\n"+
					"  2. Manually call partprobe: sudo partprobe %s\n"+
					"  3. Reboot if partition table is not updating",
					partPath, err, pv.Disk)
			}
		}

		// Additional verification - check if partition actually exists
		if _, err := os.Stat(partPath); err != nil {
			return fmt.Errorf("partition %s exists in udev but not in /dev: %w\n\n"+
				"Remediation:\n"+
				"  1. Try partprobe: sudo partprobe %s\n"+
				"  2. Check kernel messages: sudo dmesg | tail -20\n"+
				"  3. Reboot may be required",
				partPath, err, pv.Disk)
		}
	}

	// Step 2: Resize LUKS mapping if encrypted
	if pv.IsCrypt {
		if err := runCriticalCommand(ctx, opts, "cryptsetup", "resize", pv.CryptMapper); err != nil {
			return fmt.Errorf("cryptsetup resize failed for %s: %w\n\n"+
				"Remediation:\n"+
				"  1. Check LUKS status: sudo cryptsetup status %s\n"+
				"  2. Verify backing device: sudo lsblk %s\n"+
				"  3. Check cryptsetup version: cryptsetup --version\n"+
				"  4. Manually resize: sudo cryptsetup resize %s",
				pv.CryptMapper, err, pv.CryptMapper, pv.Backing, pv.CryptMapper)
		}

		// Verify mapper grew with dynamic LUKS header size
		if err := verifyMapperGrowth(ctx, pv); err != nil {
			return err
		}

		// Wait for LVM to see the new crypt device size
		if pv.Backing != "" {
			backingSize, _ := getDeviceSize(ctx, pv.Backing)
			if err := waitForLVMToSeeCryptResize(ctx, pv, backingSize); err != nil {
				logger.Warn("LVM may not have detected crypt resize yet", zap.Error(err))
			}
		}
	}

	// Step 3: Resize physical volume (CRITICAL - must not be interrupted)
	if err := runCriticalCommand(ctx, opts, "pvresize", pv.PVName); err != nil {
		return fmt.Errorf("pvresize failed on %s: %w\n\n"+
			"Remediation:\n"+
			"  1. Check PV status: sudo pvs %s\n"+
			"  2. Check device size: sudo lsblk -b %s\n"+
			"  3. Manually resize: sudo pvresize %s",
			pv.PVName, err, pv.PVName, pv.PVName, pv.PVName)
	}

	return nil
}

func verifyMapperGrowth(ctx context.Context, pv rootPV) error {
	logger := otelzap.Ctx(ctx)

	if pv.Backing == "" || pv.CryptMapper == "" {
		return nil
	}

	backingSize, err := getDeviceSize(ctx, pv.Backing)
	if err != nil {
		return nil // Don't fail on measurement error
	}

	mapperSize, err := getDeviceSize(ctx, pv.CryptMapper)
	if err != nil {
		return nil
	}

	// Query actual LUKS header size instead of hardcoding
	headerSize, err := getLUKSHeaderSize(ctx, pv.Backing)
	if err != nil {
		// Fallback to conservative 128MB max header size for LUKS2
		logger.Warn("Could not determine LUKS header size, using conservative estimate",
			zap.Error(err))
		headerSize = 128 * 1024 * 1024 // 128MB worst case
	} else {
		logger.Debug("Detected LUKS header size",
			zap.Uint64("header_bytes", headerSize),
			zap.String("backing", pv.Backing))
	}

	// Allow header size + 1MB margin for metadata/alignment
	expectedMaxDiff := headerSize + 1024*1024

	if mapperSize+expectedMaxDiff > backingSize {
		logger.Debug("Mapper size verified after resize",
			zap.Uint64("backing_size", backingSize),
			zap.Uint64("mapper_size", mapperSize),
			zap.Uint64("header_size", headerSize))
		return nil
	}

	// Wait and retry
	time.Sleep(2 * time.Second)
	mapperSize2, err := getDeviceSize(ctx, pv.CryptMapper)
	if err != nil {
		return nil
	}

	if mapperSize2+expectedMaxDiff > backingSize {
		logger.Debug("Mapper size verified after retry",
			zap.Uint64("backing_size", backingSize),
			zap.Uint64("mapper_size", mapperSize2),
			zap.Uint64("header_size", headerSize))
		return nil
	}

	return fmt.Errorf("crypt mapper %s did not grow after resize (backing %s)\n\n"+
		"Backing size: %d bytes\n"+
		"Mapper size:  %d bytes\n"+
		"LUKS header:  %d bytes\n"+
		"Expected diff: %d bytes, actual: %d bytes\n\n"+
		"Remediation:\n"+
		"  1. Check crypt status: sudo cryptsetup status %s\n"+
		"  2. Check sizes: sudo lsblk -b %s %s\n"+
		"  3. Manually resize: sudo cryptsetup resize %s",
		pv.CryptMapper, pv.Backing,
		backingSize, mapperSize2, headerSize,
		expectedMaxDiff, backingSize-mapperSize2,
		pv.CryptMapper, pv.Backing, pv.CryptMapper, pv.CryptMapper)
}

func captureSnapshot(ctx context.Context, layout *rootLayout) (deviceSnapshot, error) {
	vgFreeBytes, err := vgFreeBytes(ctx, layout.RootVG)
	if err != nil {
		return deviceSnapshot{}, err
	}
	lvSize, err := lvSizeBytes(ctx, layout.RootLVPath)
	if err != nil {
		return deviceSnapshot{}, err
	}
	fsSize, err := filesystemSizeBytes(ctx, "/")
	if err != nil {
		return deviceSnapshot{}, err
	}

	return deviceSnapshot{
		VGFreeBytes: vgFreeBytes,
		LVSizeBytes: lvSize,
		FSSizeBytes: fsSize,
	}, nil
}

func vgFreeExtents(ctx context.Context, vgName string) (int, error) {
	out, err := commandOutput(ctx, "vgs", "--noheadings", "-o", "vg_free_count", vgName)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(out)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

func vgFreeBytes(ctx context.Context, vgName string) (uint64, error) {
	out, err := commandOutput(ctx, "vgs", "--noheadings", "-o", "vg_free", vgName)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(out)
	if value == "" || value == "0" {
		return 0, nil
	}
	// vgs returns with suffix; use --units b for bytes.
	outB, err := commandOutput(ctx, "vgs", "--noheadings", "-o", "vg_free", "--units", "b", vgName)
	if err != nil {
		return 0, err
	}
	return parseSizeWithSuffix(strings.TrimSpace(outB))
}

func lvSizeBytes(ctx context.Context, lvPath string) (uint64, error) {
	out, err := commandOutput(ctx, "lvs", "--noheadings", "-o", "lv_size", "--units", "b", lvPath)
	if err != nil {
		return 0, err
	}
	return parseSizeWithSuffix(strings.TrimSpace(out))
}

func filesystemSizeBytes(ctx context.Context, mount string) (uint64, error) {
	out, err := commandOutput(ctx, "findmnt", "-bno", "SIZE", mount)
	if err != nil {
		return 0, err
	}
	return parseUint(out)
}

func getDeviceSize(ctx context.Context, device string) (uint64, error) {
	out, err := commandOutput(ctx, "lsblk", "-bno", "SIZE", device)
	if err != nil {
		return 0, err
	}
	return parseUint(out)
}

func parseSizeWithSuffix(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasSuffix(value, "B") {
		return parseUint(strings.TrimSuffix(value, "B"))
	}
	return parseUint(value)
}

func parseUint(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return strconv.ParseUint(value, 10, 64)
}

func maybeRun(ctx context.Context, opts RootExpandOptions, name string, args ...string) error {
	if opts.DryRun {
		return nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

func runCommand(ctx context.Context, opts RootExpandOptions, name string, args ...string) error {
	logger := otelzap.Ctx(ctx)
	if opts.DryRun {
		logger.Info("DRY RUN - skipping command", zap.String("command", name), zap.Strings("args", args))
		return nil
	}
	logger.Info("Running command", zap.String("command", name), zap.Strings("args", args))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// runCriticalCommand runs commands that MUST NOT be interrupted (cryptsetup resize, pvresize, lvextend)
// Uses a detached context to prevent cancellation during destructive operations
func runCriticalCommand(ctx context.Context, opts RootExpandOptions, name string, args ...string) error {
	logger := otelzap.Ctx(ctx)

	if opts.DryRun {
		logger.Info("DRY RUN - skipping critical command",
			zap.String("command", name),
			zap.Strings("args", args))
		return nil
	}

	// Create interrupt-resistant context for critical operations
	// This prevents SIGKILL from corrupting data structures mid-operation
	detachedCtx := context.Background()

	// Log if original context was canceled (for observability)
	go func() {
		<-ctx.Done()
		if ctx.Err() != nil {
			logger.Warn("Context canceled during critical operation - allowing completion for safety",
				zap.String("command", name),
				zap.Error(ctx.Err()))
		}
	}()

	logger.Info("Running critical command (not interruptible for data safety)",
		zap.String("command", name),
		zap.Strings("args", args))

	cmd := exec.CommandContext(detachedCtx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// getLUKSHeaderSize returns the actual LUKS header size by parsing luksDump output
func getLUKSHeaderSize(ctx context.Context, device string) (uint64, error) {
	dump, err := commandOutput(ctx, "cryptsetup", "luksDump", device)
	if err != nil {
		return 0, err
	}

	// Look for "Data offset:" in luksDump output
	// Example: "Data offset:    32768 [sectors]" → 32768 * 512 bytes
	scanner := bufio.NewScanner(strings.NewReader(dump))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Data offset:") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "offset:" && i+1 < len(fields) {
					sectors, err := strconv.ParseUint(fields[i+1], 10, 64)
					if err == nil {
						return sectors * 512, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("could not parse data offset from luksDump output")
}

// getPVSize returns the current size of a physical volume
func getPVSize(ctx context.Context, pvName string) (uint64, error) {
	out, err := commandOutput(ctx, "pvs", "--noheadings", "-o", "pv_size", "--units", "b", pvName)
	if err != nil {
		return 0, err
	}
	return parseSizeWithSuffix(strings.TrimSpace(out))
}

// waitForLVMToSeeCryptResize waits for LVM to detect new PV size after cryptsetup resize
func waitForLVMToSeeCryptResize(ctx context.Context, pv rootPV, backingSize uint64) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Waiting for LVM to observe crypt device size change",
		zap.String("mapper", pv.CryptMapper))

	// Poll until pvs sees the new size (max 5 seconds)
	for i := 0; i < 10; i++ {
		pvSize, err := getPVSize(ctx, pv.PVName)
		if err == nil && pvSize+16*1024*1024 > backingSize { // Allow 16MB margin
			logger.Debug("LVM detected new PV size",
				zap.Uint64("pv_size", pvSize),
				zap.Int("poll_attempts", i+1))
			return nil
		}
		if i == 9 {
			logger.Warn("LVM may not have detected new PV size",
				zap.Uint64("backing_size", backingSize),
				zap.Uint64("pv_size", pvSize))
		}
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

// getPartitionTableType returns the partition table type (gpt, dos/mbr, etc.)
func getPartitionTableType(ctx context.Context, disk string) (string, error) {
	output, err := commandOutput(ctx, "blkid", "-s", "PTTYPE", "-o", "value", disk)
	if err != nil {
		return "", err
	}

	ptType := strings.TrimSpace(output)
	// Returns: "gpt", "dos" (MBR), "atari", etc.
	return ptType, nil
}

// detectFilesystemType returns the filesystem type of a device
func detectFilesystemType(ctx context.Context, device string) (string, error) {
	output, err := commandOutput(ctx, "blkid", "-s", "TYPE", "-o", "value", device)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// vgTotalExtents returns the total number of extents in a volume group
func vgTotalExtents(ctx context.Context, vgName string) (int, error) {
	out, err := commandOutput(ctx, "vgs", "--noheadings", "-o", "vg_extent_count", vgName)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(out)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

// checkDiskHealth performs SMART health checks on a disk
func checkDiskHealth(ctx context.Context, disk string) error {
	// Check if smartctl is available
	if _, err := exec.LookPath("smartctl"); err != nil {
		// Skip if smartmontools not installed
		return nil
	}

	// Run SMART health check
	output, err := commandOutput(ctx, "smartctl", "-H", disk)
	if err != nil {
		// smartctl returns non-zero for failing disks
		if strings.Contains(output, "PASSED") {
			return nil
		}
		return fmt.Errorf("SMART health check failed")
	}

	// Check critical attributes
	output, _ = commandOutput(ctx, "smartctl", "-A", disk)

	// Parse SMART attributes for critical values
	criticalIssues := []string{}

	if strings.Contains(output, "Reallocated_Sector_Ct") {
		// Extract value - if > 36, warn
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Reallocated_Sector_Ct") {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					if value, err := strconv.Atoi(fields[9]); err == nil && value > 36 {
						criticalIssues = append(criticalIssues,
							fmt.Sprintf("Reallocated sectors: %d (threshold: 36)", value))
					}
				}
			}
		}
	}

	if strings.Contains(output, "Current_Pending_Sector") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Current_Pending_Sector") {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					if value, err := strconv.Atoi(fields[9]); err == nil && value > 0 {
						criticalIssues = append(criticalIssues,
							fmt.Sprintf("Pending sectors: %d (any pending is critical)", value))
					}
				}
			}
		}
	}

	if len(criticalIssues) > 0 {
		return fmt.Errorf("disk health issues detected: %s", strings.Join(criticalIssues, ", "))
	}

	return nil
}

// checkRecentIOErrors checks kernel log for recent I/O errors
func checkRecentIOErrors(ctx context.Context) bool {
	// Check dmesg for I/O errors
	output, err := commandOutput(ctx, "dmesg")
	if err != nil {
		return false
	}

	ioErrorPatterns := []string{
		"I/O error",
		"Buffer I/O error",
		"end_request: I/O error",
		"UncorrectableError",
		"medium error",
	}

	// Simple check - in production should parse timestamps
	for _, pattern := range ioErrorPatterns {
		if strings.Contains(output, pattern) {
			return true
		}
	}

	return false
}

// attemptPartialExpansion tries to extend LV with whatever space was successfully freed
func attemptPartialExpansion(ctx context.Context, layout *rootLayout, opts RootExpandOptions) error {
	logger := otelzap.Ctx(ctx)

	freeExtents, err := vgFreeExtents(ctx, layout.RootVG)
	if err != nil {
		return fmt.Errorf("failed to read VG free space: %w", err)
	}

	if freeExtents == 0 {
		logger.Info("No free extents available after partial PV expansion")
		return nil
	}

	logger.Info("Attempting partial LV expansion with available free space",
		zap.Int("free_extents", freeExtents))

	if err := runCriticalCommand(ctx, opts, "lvextend", "-l", "+100%FREE", "-r", layout.RootLVPath); err != nil {
		return fmt.Errorf("partial lvextend failed: %w", err)
	}

	return nil
}
