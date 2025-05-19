// pkg/kvm/transfers.go

package kvm

import (
	"os/exec"

	"go.uber.org/zap"
)

// CopyOutFromVM extracts a file from a shut-off VM to the host.
func CopyOutFromVM(vmName, guestPath, hostPath string) error {
	log := zap.L().Named("kvm.transfer")
	log.Info("📤 Copying file out of VM",
		zap.String("vm", vmName),
		zap.String("guestPath", guestPath),
		zap.String("hostPath", hostPath),
	)

	cmd := exec.Command("virt-copy-out", "-d", vmName, guestPath, hostPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("❌ virt-copy-out failed",
			zap.Error(err),
			zap.ByteString("output", output),
		)
		return err
	}

	log.Info("✅ virt-copy-out completed successfully")
	return nil
}

// CopyInToVM injects a file from the host into a shut-off VM.
func CopyInToVM(vmName, hostPath, guestDir string) error {
	log := zap.L().Named("kvm.transfer")
	log.Info("📥 Copying file into VM",
		zap.String("vm", vmName),
		zap.String("hostPath", hostPath),
		zap.String("guestDir", guestDir),
	)

	cmd := exec.Command("virt-copy-in", "-d", vmName, hostPath, guestDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("❌ virt-copy-in failed",
			zap.Error(err),
			zap.ByteString("output", output),
		)
		return err
	}

	log.Info("✅ virt-copy-in completed successfully")
	return nil
}
