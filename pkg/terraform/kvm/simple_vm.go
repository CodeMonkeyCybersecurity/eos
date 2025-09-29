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

// VM creation and IP allocation state management
var (
	vmCreationMutex sync.Mutex // Global lock for entire VM creation process
	ipMutex         sync.Mutex
	ipStateDir      = "/var/lib/eos"
)

type IPAllocations struct {
	Allocations map[string]string `json:"allocations"` // vmName -> IP
}

// Use the existing GenerateVMName from secure_vm.go

// CreateSimpleUbuntuVM creates an Ubuntu VM with hardcoded defaults: 4GB RAM, 2 vCPUs, 40GB disk
func CreateSimpleUbuntuVM(rc *eos_io.RuntimeContext, vmName string) error {
	// Lock entire VM creation to prevent race conditions
	vmCreationMutex.Lock()
	defer vmCreationMutex.Unlock()

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

	// Fix storage pool permissions (simplified approach)
	logger.Info("Fixing storage pool permissions...")
	if err := fixStoragePoolPermissions(); err != nil {
		return fmt.Errorf("failed to fix storage permissions: %w", err)
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

	// Generate cloud-init user data with static IP configured in runcmd
	userData := generateUserData(sshKeys, staticIP, vmName)

	// Create simple Terraform JSON configuration
	tfConfig := map[string]interface{}{
		"terraform": map[string]interface{}{
			"required_providers": map[string]interface{}{
				"libvirt": map[string]interface{}{
					"source":  "dmacvicar/libvirt",
					"version": "~> 0.7",
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
					"name":      vmName + "-cloudinit.iso",
					"pool":      "default",
					"user_data": userData,
					"meta_data": fmt.Sprintf("instance-id: %s\nlocal-hostname: %s", vmName, vmName),
				},
			},
			"libvirt_domain": map[string]interface{}{
				"vm": map[string]interface{}{
					"name":       vmName,
					"memory":     4096, // 4GB RAM
					"vcpu":       2,    // 2 vCPUs
					"autostart":  true, // Auto-start on boot
					"qemu_agent": true, // Enable QEMU agent
					"cloudinit":  "${libvirt_cloudinit_disk.cloudinit.id}",
					"network_interface": []interface{}{
						map[string]interface{}{
							"network_name":   "default",
							"wait_for_lease": true, // Let DHCP assign based on MAC
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
	logger.Info("Initializing Terraform")
	if err := tf.Init(ctx, tfexec.Upgrade(true)); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Apply with simplified approach (no staged apply due to complexity)
	logger.Info("Running terraform apply")
	if err := tf.Apply(ctx); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	// Fix file permissions after creation (simplified)
	logger.Info("Fixing VM file permissions for QEMU access")
	vmPattern := filepath.Join("/var/lib/libvirt/images", vmName+"*")
	vmFiles, err := filepath.Glob(vmPattern)
	if err == nil {
		for _, file := range vmFiles {
			var chownCmd *exec.Cmd
			if os.Getuid() == 0 {
				chownCmd = exec.Command("chown", "libvirt-qemu:kvm", file)
			} else {
				chownCmd = exec.Command("sudo", "chown", "libvirt-qemu:kvm", file)
			}
			chownCmd.Run() // Ignore errors - may already be correct
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

	// Success output with comprehensive information
	fmt.Printf("\n✅ Ubuntu 24.04 LTS VM created: %s\n", vmName)
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Memory: 4GB\n")
	fmt.Printf("  vCPUs: 2\n")
	fmt.Printf("  Disk: 40GB\n")
	fmt.Printf("  Network: Static IP %s (configured via cloud-init)\n", staticIP)
	fmt.Printf("  Auto-start: Enabled\n")
	fmt.Printf("  QEMU Agent: Enabled\n")
	fmt.Printf("  SSH Keys: %d configured\n", len(sshKeys))
	fmt.Printf("\nAccess:\n")
	fmt.Printf("  SSH: ssh ubuntu@%s\n", staticIP)
	fmt.Printf("  Console: virsh console %s\n", vmName)
	fmt.Printf("\nManagement:\n")
	fmt.Printf("  Stop: virsh shutdown %s\n", vmName)
	fmt.Printf("  Start: virsh start %s\n", vmName)
	fmt.Printf("  Status: virsh list --all\n")
	fmt.Printf("  Info: virsh dominfo %s\n", vmName)
	fmt.Printf("  Destroy: cd %s && terraform destroy\n", workingDir)

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

// generateUserData creates cloud-init user data with SSH keys and static IP in runcmd
func generateUserData(sshKeys []string, staticIP, vmName string) string {
	keys := make([]string, len(sshKeys))
	for i, key := range sshKeys {
		keys[i] = "      - " + strings.TrimSpace(key)
	}
	keyString := strings.Join(keys, "\n")

	return fmt.Sprintf(`#cloud-config
hostname: %s
manage_etc_hosts: true
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
%s

package_update: true
packages:
  - qemu-guest-agent

runcmd:
  - |
    cat > /etc/netplan/99-static.yaml <<EOF
    network:
      version: 2
      ethernets:
        ens3:
          dhcp4: false
          addresses: [%s/24]
          gateway4: 192.168.122.1
          nameservers:
            addresses: [8.8.8.8, 8.8.4.4]
    EOF
  - netplan apply
  - systemctl enable --now qemu-guest-agent

ssh_pwauth: false
disable_root: true`, vmName, keyString, staticIP)
}

// checkKVMPrerequisites verifies all KVM-related requirements
func checkKVMPrerequisites() error {
	// Check if KVM device exists
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("KVM not available - ensure virtualization is enabled in BIOS")
	}

	return nil
}

// fixStoragePoolPermissions applies simple, reliable permission fixes
func fixStoragePoolPermissions() error {
	// Simple approach: make the images directory accessible
	cmds := [][]string{
		{"chmod", "1777", "/var/lib/libvirt/images"},
		{"chown", "root:kvm", "/var/lib/libvirt/images"},
	}

	for _, args := range cmds {
		var cmd *exec.Cmd
		if os.Getuid() == 0 {
			cmd = exec.Command(args[0], args[1:]...)
		} else {
			fullArgs := append([]string{"sudo"}, args...)
			cmd = exec.Command(fullArgs[0], fullArgs[1:]...)
		}
		cmd.Run() // Ignore errors - permissions may already be correct
	}

	return nil
}