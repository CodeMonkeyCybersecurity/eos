// pkg/kvm/transfers.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

var (
	SourceVM   string
	SourcePath string
	DestVM     string
	DestPath   string
)

func SyncFileBetweenVMs(sourceVM, guestPath, destVM, destGuestPath string) error {
	log := zap.L().Named("kvm.sync")

	// Derive a predictable temp filename
	baseName := filepath.Base(guestPath)
	timestamp := time.Now().Format("20060102_150405")
	hostDir := "/var/lib/eos/transfer"
	hostPath := filepath.Join(
		hostDir,
		fmt.Sprintf("%s_from-%s_to-%s_%s", timestamp, sourceVM, destVM, baseName),
	)

	log.Info("🔁 Starting full VM-to-VM file sync",
		zap.String("sourceVM", sourceVM),
		zap.String("guestPath", guestPath),
		zap.String("intermediate", hostPath),
		zap.String("destVM", destVM),
		zap.String("destGuestPath", destGuestPath),
	)

	if err := CopyOutFromVM(sourceVM, guestPath, hostPath); err != nil {
		log.Error("❌ Copy out from source VM failed", zap.Error(err))
		return fmt.Errorf("extract from %s failed: %w", sourceVM, err)
	}

	destDir := filepath.Dir(destGuestPath)
	if err := CopyInToVM(destVM, hostPath, destDir); err != nil {
		log.Error("❌ Copy into destination VM failed", zap.Error(err))
		return fmt.Errorf("inject to %s failed: %w", destVM, err)
	}

	log.Info("✅ VM-to-VM file sync complete",
		zap.String("source", sourceVM),
		zap.String("dest", destVM),
		zap.String("file", guestPath),
	)

	return nil
}

// CopyOutFromVM extracts a file from a shut-off VM to the host.
func CopyOutFromVM(vmName, guestPath, hostFile string) error {
	log := zap.L().Named("kvm.transfer")
	hostDir := filepath.Dir(hostFile)
	tempName := filepath.Base(guestPath)

	log.Info("📤 Preparing to copy file out of VM",
		zap.String("vm", vmName),
		zap.String("guestPath", guestPath),
		zap.String("hostDir", hostDir),
		zap.String("hostFile", hostFile),
	)

	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		log.Error("❌ Failed to create host directory", zap.Error(err))
		return fmt.Errorf("create host dir failed: %w", err)
	}

	cmd := exec.Command("virt-copy-out", "-d", vmName, guestPath, hostDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("❌ virt-copy-out failed",
			zap.Error(err),
			zap.ByteString("output", output),
			zap.Strings("args", cmd.Args),
		)
		return fmt.Errorf("virt-copy-out failed: %w", err)
	}

	// Rename to the expected full path if needed
	actual := filepath.Join(hostDir, tempName)
	if actual != hostFile {
		log.Info("🔁 Renaming extracted file", zap.String("from", actual), zap.String("to", hostFile))
		if err := os.Rename(actual, hostFile); err != nil {
			log.Error("❌ Failed to rename extracted file", zap.Error(err))
			return fmt.Errorf("failed to rename extracted file: %w", err)
		}
	}

	log.Info("✅ virt-copy-out completed and renamed successfully", zap.String("file", hostFile))
	return nil
}

// CopyInToVM injects a file from the host into a shut-off VM.
func CopyInToVM(vmName, hostPath, guestDir string) error {
	log := zap.L().Named("kvm.transfer")

	log.Info("📥 Preparing to copy file into VM",
		zap.String("vm", vmName),
		zap.String("hostPath", hostPath),
		zap.String("guestDir", guestDir),
	)

	// Check if the host file exists
	info, err := os.Stat(hostPath)
	if err != nil {
		log.Error("❌ Host file not found",
			zap.String("path", hostPath),
			zap.Error(err),
		)
		return fmt.Errorf("host file not found: %w", err)
	}
	if info.IsDir() {
		log.Error("❌ Host path is a directory, not a file", zap.String("path", hostPath))
		return fmt.Errorf("host path is a directory, not a file: %s", hostPath)
	}

	// Use virt-copy-in to insert the file
	cmd := exec.Command("virt-copy-in", "-d", vmName, hostPath, guestDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("❌ virt-copy-in failed",
			zap.Error(err),
			zap.ByteString("output", output),
			zap.Strings("args", cmd.Args),
		)
		return fmt.Errorf("virt-copy-in failed: %w", err)
	}

	log.Info("✅ virt-copy-in completed successfully",
		zap.String("vm", vmName),
		zap.String("file", hostPath),
		zap.String("dest", guestDir),
	)
	return nil
}
