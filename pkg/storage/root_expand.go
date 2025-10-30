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
		return errors.New("no LUKS-backed PVs detected but --luks was specified")
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

	for _, pv := range layout.PVs {
		report := pvReport{
			PVName:  pv.PVName,
			IsCrypt: pv.IsCrypt,
			Backing: pv.Backing,
		}

		if size, err := getDeviceSize(ctx, pv.PVName); err == nil {
			report.PVSize = size
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

		if err := processPV(ctx, pv, opts); err != nil {
			return err
		}

		pvReports = append(pvReports, report)
	}

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
		if err := runCommand(ctx, opts, "lvextend", "-l", "+100%FREE", "-r", layout.RootLVPath); err != nil {
			return fmt.Errorf("lvextend failed: %w", err)
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
	fmt.Printf("\nRoot LV: %s (VG: %s)\n", layout.RootLVPath, layout.RootVG)
	fmt.Println("This will expand the root logical volume and filesystem online using the following PVs:")
	for _, pv := range layout.PVs {
		fmt.Printf("  - %s (backing: %s, crypt: %t)\n", pv.PVName, pv.Backing, pv.IsCrypt)
	}
	fmt.Print("\nProceed? (yes/no): ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("operation cancelled by user")
	}
	return nil
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

	if opts.AllowPartitionGrow && pv.Disk != "" && pv.PartNum != "" {
		_ = runCommand(ctx, opts, "sgdisk", "-e", pv.Disk)
		if err := runCommand(ctx, opts, "growpart", pv.Disk, pv.PartNum); err != nil {
			return fmt.Errorf("growpart failed for %s:%s: %w", pv.Disk, pv.PartNum, err)
		}
		_ = runCommand(ctx, opts, "udevadm", "settle")
	}

	if pv.IsCrypt {
		if err := runCommand(ctx, opts, "cryptsetup", "resize", pv.CryptMapper); err != nil {
			return fmt.Errorf("cryptsetup resize failed for %s: %w", pv.CryptMapper, err)
		}
		if err := verifyMapperGrowth(ctx, pv); err != nil {
			return err
		}
	}

	if err := runCommand(ctx, opts, "pvresize", pv.PVName); err != nil {
		return fmt.Errorf("pvresize failed on %s: %w", pv.PVName, err)
	}

	return nil
}

func verifyMapperGrowth(ctx context.Context, pv rootPV) error {
	if pv.Backing == "" || pv.CryptMapper == "" {
		return nil
	}

	backingSize, err := getDeviceSize(ctx, pv.Backing)
	if err != nil {
		return nil
	}
	mapperSize, err := getDeviceSize(ctx, pv.CryptMapper)
	if err != nil {
		return nil
	}

	// Allow small discrepancies for LUKS header overhead.
	if mapperSize+16*1024 > backingSize {
		return nil
	}

	time.Sleep(2 * time.Second)
	mapperSize2, err := getDeviceSize(ctx, pv.CryptMapper)
	if err != nil {
		return nil
	}
	if mapperSize2+16*1024 > backingSize {
		return nil
	}

	return fmt.Errorf("crypt mapper %s did not grow after resize (backing %s)", pv.CryptMapper, pv.Backing)
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
