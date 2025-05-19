package kvm

import (
	"fmt"
	"os/exec"
)

func CopyOutFromVM(vmName, guestPath, hostPath string) error {
	cmd := exec.Command("virt-copy-out", "-d", vmName, guestPath, hostPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("virt-copy-out failed: %s", string(output))
	}
	return nil
}

func CopyInToVM(vmName, hostPath, guestDir string) error {
	cmd := exec.Command("virt-copy-in", "-d", vmName, hostPath, guestDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("virt-copy-in failed: %s", string(output))
	}
	return nil
}
