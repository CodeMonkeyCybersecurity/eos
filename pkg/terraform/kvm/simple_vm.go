// pkg/terraform/kvm/simple_vm.go
// MINIMAL VM CREATION - Just the essentials

package kvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Use the existing GenerateVMName from secure_vm.go

// CreateSimpleUbuntuVM creates an Ubuntu VM with hardcoded defaults: 4GB RAM, 2 vCPUs, 40GB disk
func CreateSimpleUbuntuVM(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check prerequisites
	logger.Info("Checking KVM/libvirt prerequisites...")

	// Check if terraform is installed
	if err := checkTerraform(); err != nil {
		return fmt.Errorf("terraform prerequisite check failed: %w", err)
	}

	// Check if libvirt is available
	if err := checkLibvirt(); err != nil {
		return fmt.Errorf("libvirt prerequisite check failed: %w", err)
	}

	// Check if KVM is available
	if err := checkKVM(); err != nil {
		return fmt.Errorf("KVM prerequisite check failed: %w", err)
	}

	// Using /tmp for storage - no permission checks needed
	logger.Info("Using /tmp for VM storage - bypasses permission issues")

	// Create working directory
	workingDir := filepath.Join("/tmp", "terraform-"+vmName)
	if err := os.MkdirAll(workingDir, 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	logger.Info("Created working directory", zap.String("path", workingDir))

	// Create simple Terraform JSON configuration
	tfConfig := map[string]interface{}{
		"terraform": map[string]interface{}{
			"required_providers": map[string]interface{}{
				"libvirt": map[string]interface{}{
					"source": "dmacvicar/libvirt",
				},
			},
		},
		"provider": map[string]interface{}{
			"libvirt": map[string]interface{}{
				"uri": "qemu:///system",
			},
		},
		"resource": map[string]interface{}{
			"libvirt_volume": map[string]interface{}{
				"ubuntu_base": map[string]interface{}{
					"name":   "/tmp/" + vmName + "-base.qcow2",
					"source": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
					"format": "qcow2",
				},
				"vm_disk": map[string]interface{}{
					"name":           "/tmp/" + vmName + ".qcow2",
					"base_volume_id": "${libvirt_volume.ubuntu_base.id}",
					"size":           42949672960, // 40GB
				},
			},
			"libvirt_cloudinit_disk": map[string]interface{}{
				"cloudinit": map[string]interface{}{
					"name": "/tmp/" + vmName + "-cloudinit.iso",
					"user_data": `#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: $6$rounds=4096$saltsalt$7xmvWaIOaKB5QZEV.IXnP4YW9BJHZkDSdTLqk8xrNDrPP2LR0JcR9Qx7XQqGBFqJmYqVqLqaWgtmNDYiJQfz71

package_update: true
packages:
  - qemu-guest-agent`,
					"meta_data": fmt.Sprintf("instance-id: %s\nlocal-hostname: %s", vmName, vmName),
				},
			},
			"libvirt_domain": map[string]interface{}{
				"vm": map[string]interface{}{
					"name":      vmName,
					"memory":    4096, // 4GB RAM
					"vcpu":      2,    // 2 vCPUs
					"cloudinit": "${libvirt_cloudinit_disk.cloudinit.id}",
					"network_interface": []interface{}{
						map[string]interface{}{
							"network_name":   "default",
							"wait_for_lease": true,
						},
					},
					"disk": []interface{}{
						map[string]interface{}{
							"volume_id": "${libvirt_volume.vm_disk.id}",
						},
					},
					"console": []interface{}{
						map[string]interface{}{
							"type":        "pty",
							"target_type": "serial",
							"target_port": "0",
						},
					},
					"graphics": []interface{}{
						map[string]interface{}{
							"type":        "spice",
							"listen_type": "none",
							"autoport":    true,
						},
					},
				},
			},
		},
		"output": map[string]interface{}{
			"vm_ip": map[string]interface{}{
				"value": "${libvirt_domain.vm.network_interface[0].addresses[0]}",
			},
		},
	}

	// Write configuration to file
	configPath := filepath.Join(workingDir, "main.tf.json")
	configData, err := json.MarshalIndent(tfConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Wrote Terraform configuration", zap.String("path", configPath))

	// Run Terraform
	tf, err := tfexec.NewTerraform(workingDir, "terraform")
	if err != nil {
		return fmt.Errorf("failed to create terraform executor: %w", err)
	}

	ctx := context.Background()

	// Initialize
	logger.Info("Running terraform init")
	if err := tf.Init(ctx, tfexec.Upgrade(true)); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Apply (auto-approve not needed with terraform-exec)
	logger.Info("Running terraform apply")
	if err := tf.Apply(ctx); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	// Get outputs
	outputs, err := tf.Output(ctx)
	if err != nil {
		logger.Warn("Failed to get outputs", zap.Error(err))
	} else if outputs != nil {
		if vmIP, ok := outputs["vm_ip"]; ok {
			logger.Info("VM IP address", zap.Any("ip", vmIP.Value))
		}
	}

	// Print success message
	fmt.Printf("\n✅ VM created: %s\n", vmName)
	fmt.Printf("Storage: /tmp (VM files: /tmp/%s-*.qcow2)\n", vmName)
	fmt.Printf("Working directory: %s\n", workingDir)
	fmt.Printf("\nVerify with:\n")
	fmt.Printf("  virsh list --all\n")
	fmt.Printf("  virsh dominfo %s\n", vmName)
	fmt.Printf("  ls -la /tmp/%s-*\n", vmName)
	fmt.Printf("\nConnect with:\n")
	fmt.Printf("  virsh console %s  (password: ubuntu)\n", vmName)
	fmt.Printf("\nCleanup:\n")
	fmt.Printf("  cd %s && terraform destroy -auto-approve\n", workingDir)
	fmt.Printf("  # VM files in /tmp will be cleaned up on reboot\n")

	return nil
}

// checkTerraform verifies terraform is installed and accessible
func checkTerraform() error {
	// Use exec.LookPath instead of tfexec.LookPath
	if _, err := os.LookupEnv("PATH"); !err {
		return fmt.Errorf("PATH environment variable not set")
	}

	// Check if terraform exists in PATH
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		terraformPath := filepath.Join(dir, "terraform")
		if info, err := os.Stat(terraformPath); err == nil && !info.IsDir() {
			return nil // Found terraform
		}
	}

	return fmt.Errorf("terraform not found in PATH - install from https://terraform.io")
}

// checkLibvirt verifies libvirt daemon is running
func checkLibvirt() error {
	// Try to connect to libvirt socket
	if _, err := os.Stat("/var/run/libvirt/libvirt-sock"); err != nil {
		return fmt.Errorf("libvirt daemon not running - run: sudo systemctl start libvirtd")
	}
	return nil
}

// checkKVM verifies KVM is available
func checkKVM() error {
	// Check if KVM device exists
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("KVM not available - ensure virtualization is enabled in BIOS")
	}
	return nil
}