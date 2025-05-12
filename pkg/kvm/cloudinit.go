// pkg/kvm/cloudinit.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"go.uber.org/zap"
)

// ProvisionCloudInitVM generates metadata and a seed.img for virt-install.
// NOTE: does not yet run virt-install.
func ProvisionCloudInitVM(log *zap.Logger, cfg CloudInitConfig) error {
	// Apply defaults
	if cfg.DiskSizeGB == 0 {
		cfg.DiskSizeGB = 20
	}
	if cfg.UseUEFI {
		if _, err := os.Stat("/usr/share/OVMF/OVMF_CODE.fd"); err != nil {
			log.Warn("UEFI requested but OVMF not found — falling back to BIOS")
			cfg.UseUEFI = false
		}
	}

	// Check for required tools
	if _, err := exec.LookPath("cloud-localds"); err != nil {
		return fmt.Errorf("cloud-localds is not installed: %w", err)
	}
	if _, err := exec.LookPath("virt-install"); err != nil {
		return fmt.Errorf("virt-install is not installed: %w", err)
	}

	// Validate cloud image
	if _, err := os.Stat(cfg.CloudImg); err != nil {
		return fmt.Errorf("missing base cloud image: %w", err)
	}

	vm := cfg.VMName
	tmp := os.TempDir()
	userDataPath := filepath.Join(tmp, vm+"-user-data")
	metaDataPath := filepath.Join(tmp, vm+"-meta-data")
	seedImg := filepath.Join(tmp, vm+"-seed.img")
	vmDisk := filepath.Join("/var/lib/libvirt/images", vm+".qcow2")
	osVariant := "ubuntu20.04" // safe default

	// Load SSH key
	key := cfg.PublicKey
	if fi, err := os.Stat(key); err == nil && !fi.IsDir() {
		data, err := os.ReadFile(key)
		if err != nil {
			return fmt.Errorf("failed to read SSH key: %w", err)
		}
		key = string(data)
	}

	// Write user-data
	userData := fmt.Sprintf(`#cloud-config
users:
  - name: debugadmin
    ssh-authorized-keys:
      - %s
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: sudo
    shell: /bin/bash
`, key)
	if err := os.WriteFile(userDataPath, []byte(userData), 0644); err != nil {
		return fmt.Errorf("failed to write user-data: %w", err)
	}

	// Write meta-data
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", vm, vm)
	if err := os.WriteFile(metaDataPath, []byte(metaData), 0644); err != nil {
		return fmt.Errorf("failed to write meta-data: %w", err)
	}

	// Generate seed.img
	cmdSeed := exec.Command("cloud-localds", seedImg, userDataPath, metaDataPath)
	log.Info("💿 Running cloud-localds", zap.String("cmd", cmdSeed.String()))
	if out, err := cmdSeed.CombinedOutput(); err != nil {
		log.Error("cloud-localds failed", zap.ByteString("output", out), zap.Error(err))
		return fmt.Errorf("cloud-localds error: %w", err)
	}

	// Create VM disk
	cmdDisk := exec.Command("qemu-img", "create", "-f", "qcow2", vmDisk, fmt.Sprintf("%dG", cfg.DiskSizeGB))
	log.Info("📦 Creating VM disk", zap.String("path", vmDisk))
	if out, err := cmdDisk.CombinedOutput(); err != nil {
		log.Error("Disk creation failed", zap.ByteString("output", out), zap.Error(err))
		return fmt.Errorf("disk creation error: %w", err)
	}

	// Build virt-install command
	args := []string{
		"--name", vm,
		"--ram", "2048",
		"--vcpus", "2",
		"--os-variant", osVariant,
		"--network", "network=default,model=virtio",
		"--graphics", "none",
		"--noautoconsole",
		"--disk", fmt.Sprintf("path=%s,format=qcow2", vmDisk),
		"--disk", fmt.Sprintf("path=%s,device=cdrom", seedImg),
		"--disk", fmt.Sprintf("path=%s,device=disk", cfg.CloudImg),
	}

	if cfg.UseUEFI {
		args = append(args, "--boot", "uefi")
	} else {
		args = append(args, "--boot", "bios")
	}

	cmdVirt := exec.Command("virt-install", args...)
	log.Info("🚀 Running virt-install", zap.Strings("args", args))
	cmdVirt.Stdout = os.Stdout
	cmdVirt.Stderr = os.Stderr
	if err := cmdVirt.Run(); err != nil {
		return fmt.Errorf("virt-install failed: %w", err)
	}

	log.Info("✅ cloud-init VM provisioned", zap.String("vm", vm))
	return nil
}
