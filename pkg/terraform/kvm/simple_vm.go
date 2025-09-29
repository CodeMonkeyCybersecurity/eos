// pkg/terraform/kvm/simple_vm.go
// MINIMAL VM CREATION - Just the essentials

package kvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// IP allocation state management
var (
	ipMutex    sync.Mutex
	ipStateDir = "/var/lib/eos"
)

type IPAllocations struct {
	Allocations map[string]string `json:"allocations"` // vmName -> IP
}

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

	// Check all KVM prerequisites
	if err := checkKVMPrerequisites(); err != nil {
		return fmt.Errorf("KVM prerequisite check failed: %w", err)
	}

	// Fix permissions on libvirt images directory (simplified)
	logger.Info("Fixing libvirt storage permissions...")
	var err error
	if os.Getuid() == 0 {
		err = exec.Command("chmod", "755", "/var/lib/libvirt/images").Run()
	} else {
		err = exec.Command("sudo", "chmod", "755", "/var/lib/libvirt/images").Run()
	}
	if err != nil {
		return fmt.Errorf("failed to fix permissions: %w", err)
	}

	// Remove duplicate terraform check - already done above

	// Find SSH keys (REQUIRED for security)
	sshKeys := findSSHKeys()
	if len(sshKeys) == 0 {
		return fmt.Errorf("No SSH keys found in ~/.ssh/, /root/.ssh/, or /home/$SUDO_USER/.ssh/\n" +
			"Please create SSH keys first: ssh-keygen -t rsa -b 4096")
	}
	logger.Info("Found SSH keys for VM access", zap.Int("key_count", len(sshKeys)))

	// Create working directory
	workingDir := filepath.Join("/tmp", "terraform-"+vmName)
	if err := os.MkdirAll(workingDir, 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	logger.Info("Created working directory", zap.String("path", workingDir))

	// Allocate static IP with persistent state management
	staticIP, err := allocateStaticIP(vmName)
	if err != nil {
		return fmt.Errorf("failed to allocate static IP: %w", err)
	}
	defer func() {
		if err != nil {
			releaseStaticIP(vmName) // Rollback on failure
		}
	}()

	// Generate cloud-init configuration with static IP
	userData, err := generateCloudInit(sshKeys, staticIP)
	if err != nil {
		return fmt.Errorf("failed to generate cloud-init: %w", err)
	}

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
					"name":   vmName + "-base.qcow2",
					"source": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
					"pool":   "default",
					"format": "qcow2",
				},
				"vm_disk": map[string]interface{}{
					"name":           vmName + ".qcow2",
					"base_volume_id": "${libvirt_volume.ubuntu_base.id}",
					"pool":           "default",
					"size":           42949672960, // 40GB
				},
			},
			"libvirt_cloudinit_disk": map[string]interface{}{
				"cloudinit": map[string]interface{}{
					"name": vmName + "-cloudinit.iso",
					"pool": "default",
					"user_data": userData,
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
							"addresses":      []string{staticIP},
							"wait_for_lease": false, // Static IP, no DHCP lease needed
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
				"value": staticIP,
			},
			"vm_mac": map[string]interface{}{
				"value": "${libvirt_domain.vm.network_interface[0].mac}",
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

	// Debug output only if DEBUG environment variable is set
	if os.Getenv("DEBUG") != "" {
		fmt.Printf("\n=== Generated Terraform Config ===\n%s\n=== End Config ===\n", string(configData))
	}

	// Run Terraform
	tf, err := tfexec.NewTerraform(workingDir, "terraform")
	if err != nil {
		return fmt.Errorf("failed to create terraform executor: %w", err)
	}

	ctx := context.Background()

	// Enable debug logging only if DEBUG environment variable is set
	if os.Getenv("DEBUG") != "" {
		os.Setenv("TF_LOG", "DEBUG")
		os.Setenv("TF_LOG_PATH", filepath.Join(workingDir, "terraform-debug.log"))
		logger.Info("Debug logging enabled", zap.String("log_path", filepath.Join(workingDir, "terraform-debug.log")))
	}

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

	// Fix file permissions after creation
	logger.Info("Fixing VM file permissions for QEMU access")
	vmPattern := filepath.Join("/var/lib/libvirt/images", vmName+"*")
	vmFiles, err := filepath.Glob(vmPattern)
	if err == nil {
		for _, file := range vmFiles {
			if os.Getuid() == 0 {
				exec.Command("chmod", "644", file).Run()
				exec.Command("chown", "libvirt-qemu:kvm", file).Run()
			} else {
				exec.Command("sudo", "chmod", "644", file).Run()
				exec.Command("sudo", "chown", "libvirt-qemu:kvm", file).Run()
			}
		}
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

	// Print success message with static IP
	fmt.Printf("\n✅ Ubuntu 24.04 LTS VM created: %s\n", vmName)
	fmt.Printf("SSH Keys: %d keys configured\n", len(sshKeys))
	fmt.Printf("Working directory: %s\n", workingDir)
	fmt.Printf("\n✅ VM Ready!\n")
	fmt.Printf("Static IP Address: %s\n", staticIP)
	fmt.Printf("SSH Access: ssh ubuntu@%s\n", staticIP)

	fmt.Printf("\nVerify:\n")
	fmt.Printf("  virsh list --all\n")
	fmt.Printf("  virsh dominfo %s\n", vmName)

	fmt.Printf("\nCleanup:\n")
	fmt.Printf("  cd %s && terraform destroy -auto-approve\n", workingDir)

	return nil
}

// checkTerraform verifies terraform is installed and accessible
func checkTerraform() error {
	// Use exec.LookPath for proper PATH lookup
	if _, err := exec.LookPath("terraform"); err != nil {
		return fmt.Errorf("terraform not found in PATH - install from https://terraform.io")
	}
	return nil
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

// findSSHKeys looks for SSH public keys in multiple locations
func findSSHKeys() []string {
	var keys []string
	var sshDirs []string

	// Check /root/.ssh (current process running as root)
	sshDirs = append(sshDirs, "/root/.ssh")

	// If running via sudo, also check original user's .ssh
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		sshDirs = append(sshDirs, filepath.Join("/home", sudoUser, ".ssh"))
	}

	// Also check current user's home as fallback
	if homeDir, err := os.UserHomeDir(); err == nil {
		sshDir := filepath.Join(homeDir, ".ssh")
		sshDirs = append(sshDirs, sshDir)
	}

	// Scan all directories for keys
	for _, sshDir := range sshDirs {
		entries, err := os.ReadDir(sshDir)
		if err != nil {
			continue // Skip if directory doesn't exist or can't read
		}

		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".pub" {
				keyPath := filepath.Join(sshDir, entry.Name())
				if keyData, err := os.ReadFile(keyPath); err == nil {
					// Clean up the key (remove newlines) and avoid duplicates
					cleanKey := strings.TrimSpace(string(keyData))
					if cleanKey != "" && !contains(keys, cleanKey) {
						keys = append(keys, cleanKey)
					}
				}
			}
		}
	}

	return keys
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// allocateStaticIP allocates a static IP with persistent state management
func allocateStaticIP(vmName string) (string, error) {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	// Ensure state directory exists
	if err := os.MkdirAll(ipStateDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}

	ipStateFile := filepath.Join(ipStateDir, "ip-allocations.json")

	// Load existing allocations
	allocations := make(map[string]string)
	if data, err := os.ReadFile(ipStateFile); err == nil {
		json.Unmarshal(data, &allocations)
	}

	// Check if VM already has an IP
	if ip, exists := allocations[vmName]; exists {
		return ip, nil
	}

	// Find next available IP in range 100-200
	for i := 100; i <= 200; i++ {
		ip := fmt.Sprintf("192.168.122.%d", i)
		used := false
		for _, allocatedIP := range allocations {
			if allocatedIP == ip {
				used = true
				break
			}
		}
		if !used {
			allocations[vmName] = ip
			data, _ := json.Marshal(allocations)
			os.WriteFile(ipStateFile, data, 0644)
			return ip, nil
		}
	}

	return "", fmt.Errorf("no IPs available in pool (192.168.122.100-200)")
}

// releaseStaticIP releases an IP allocation for rollback
func releaseStaticIP(vmName string) {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	ipStateFile := filepath.Join(ipStateDir, "ip-allocations.json")
	allocations := make(map[string]string)
	if data, err := os.ReadFile(ipStateFile); err == nil {
		json.Unmarshal(data, &allocations)
	}

	delete(allocations, vmName)
	data, _ := json.Marshal(allocations)
	os.WriteFile(ipStateFile, data, 0644)
}

// generateCloudInit creates cloud-init user data with SSH keys and static IP configuration
func generateCloudInit(sshKeys []string, staticIP string) (string, error) {
	if len(sshKeys) == 0 {
		return "", fmt.Errorf("no SSH keys provided")
	}

	userData := `#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:`

	for _, key := range sshKeys {
		userData += fmt.Sprintf("\n      - %s", key)
	}

	userData += fmt.Sprintf(`

package_update: true
packages:
  - qemu-guest-agent

ssh_pwauth: false
disable_root: true

# Static IP configuration
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses:
        - %s/24
      gateway4: 192.168.122.1
      nameservers:
        addresses:
          - 192.168.122.1
          - 8.8.8.8

runcmd:
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent`, staticIP)

	return userData, nil
}

// getVMIP is removed - we use static IP assignment instead of dynamic discovery

// checkKVMPrerequisites verifies all KVM-related requirements
func checkKVMPrerequisites() error {
	// Check if KVM device exists
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("KVM not available - ensure virtualization is enabled in BIOS")
	}

	return nil
}