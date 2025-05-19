// pkg/kvm/transfers.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"go.uber.org/zap"
)

// CopyOutFromVM extracts a file from a shut-off VM to the host.
func CopyOutFromVM(vmName, guestPath, hostFile string) error {
	log := zap.L().Named("kvm.transfer")
	hostDir := filepath.Dir(hostFile)

	log.Info("📤 Preparing to copy file out of VM",
		zap.String("vm", vmName),
		zap.String("guestPath", guestPath),
		zap.String("hostDir", hostDir),
		zap.String("hostFile", hostFile),
	)

	// Ensure target directory exists
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		log.Error("❌ Failed to create host directory", zap.Error(err))
		return fmt.Errorf("create host dir failed: %w", err)
	}

	// Call virt-copy-out to the directory (not the full path!)
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

	log.Info("✅ virt-copy-out completed successfully", zap.String("file", guestPath))
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

	// Check source file
	if _, err := os.Stat(hostPath); err != nil {
		log.Error("❌ Host file not found", zap.String("path", hostPath), zap.Error(err))
		return fmt.Errorf("host file not found: %w", err)
	}

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

	log.Info("✅ virt-copy-in completed successfully", zap.String("file", hostPath))
	return nil
}
