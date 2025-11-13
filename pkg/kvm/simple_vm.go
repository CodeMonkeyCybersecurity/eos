//go:build linux

// pkg/kvm/simple_vm.go
// Direct virsh-based VM creation using libvirt/virsh

package kvm

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	baseImageURL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
	isoDir       = "/srv/iso"
	vmPrefix     = "eos-kvm"
)

// VM creation state management
var (
	vmCreationMutex sync.Mutex // Global lock for entire VM creation process
)

// SimpleVMConfig holds simplified configuration for quick VM creation
type SimpleVMConfig struct {
	Name     string
	Memory   string   // in MB
	VCPUs    string
	DiskSize string   // in GB
	Network  string
	SSHKeys  []string // Additional SSH public keys to inject
}

// CreateSimpleUbuntuVM creates an Ubuntu VM using virsh directly
func CreateSimpleUbuntuVM(rc *eos_io.RuntimeContext, vmName string) error {
	// Lock entire VM creation to prevent race conditions
	vmCreationMutex.Lock()
	defer vmCreationMutex.Unlock()

	logger := otelzap.Ctx(rc.Ctx)

	// Check prerequisites
	logger.Info("Checking KVM/libvirt prerequisites...")
	if err := checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// Create VM configuration with defaults
	config := SimpleVMConfig{
		Name:     vmName,
		Memory:   "4096",
		VCPUs:    "2",
		DiskSize: "40",
		Network:  "default",
	}

	// Input validation
	if err := validateSimpleVMConfig(&config); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Generate VM name if not provided
	if config.Name == "" {
		config.Name = generateVMName()
	}

	// Clean up any existing domain with same name for idempotency
	logger.Info("Cleaning up potential domain conflicts", zap.String("vm_name", config.Name))
	cleanupExistingDomain(config.Name, &logger)

	// Create working directory
	seedDir := filepath.Join(isoDir, config.Name)
	if err := os.MkdirAll(seedDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create seed directory: %w", err)
	}

	logger.Info("Creating Ubuntu 24.04 VM", zap.String("name", config.Name))

	// Find existing SSH keys
	existingKeys := findSSHKeys()
	if len(existingKeys) > 0 {
		logger.Info("Found existing SSH keys", zap.Int("count", len(existingKeys)))
		config.SSHKeys = append(config.SSHKeys, existingKeys...)
	}

	// Generate SSH keypair (ed25519)
	_, pubKey, err := generateSSHKeyED25519(seedDir, config.Name)
	if err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}

	// Add generated key to the list
	config.SSHKeys = append([]string{pubKey}, config.SSHKeys...)
	// SECURITY P2 #6: Log key fingerprint instead of path to avoid information disclosure
	logger.Info("Generated ed25519 SSH keypair",
		zap.String("key_type", "ed25519"),
		zap.String("note", "Private key generated - location not logged for security"))

	// Create cloud-init files
	if err := createCloudInit(seedDir, config); err != nil {
		return fmt.Errorf("failed to create cloud-init: %w", err)
	}

	// Generate seed.img
	seedImgPath := filepath.Join(seedDir, "seed.img")
	if err := generateSeedImage(seedDir, seedImgPath); err != nil {
		return fmt.Errorf("failed to generate seed image: %w", err)
	}

	// Download or copy base image
	baseImagePath := filepath.Join(isoDir, "ubuntu-24.04-base.img")
	if _, err := os.Stat(baseImagePath); os.IsNotExist(err) {
		logger.Info("Downloading Ubuntu base image")
		if err := downloadBaseImage(baseImagePath, &logger); err != nil {
			return fmt.Errorf("failed to get base image: %w", err)
		}
	} else {
		logger.Info("Using existing base image", zap.String("path", baseImagePath))
	}

	// Create VM disk from base
	vmDiskPath := filepath.Join(isoDir, config.Name+".qcow2")
	if err := createVMDisk(baseImagePath, vmDiskPath, config.DiskSize, &logger); err != nil {
		return fmt.Errorf("failed to create VM disk: %w", err)
	}

	// Launch VM with virt-install
	if err := launchVM(config, vmDiskPath, seedImgPath, &logger); err != nil {
		return fmt.Errorf("failed to launch VM: %w", err)
	}

	// Get VM IP
	ip, _ := waitForVMIP(config.Name, 30, &logger)

	// SECURITY P2 #6: Don't log SSH key paths - information disclosure
	logger.Info("VM created successfully",
		zap.String("name", config.Name),
		zap.String("ip", ip),
		zap.String("ssh_key_status", "configured"))

	// Log success with structured logging (user-facing output should be via dedicated output package)
	logger.Info("Ubuntu 24.04 VM created successfully",
		zap.String("vm_name", config.Name),
		zap.String("memory_mb", config.Memory),
		zap.String("vcpus", config.VCPUs),
		zap.String("disk_gb", config.DiskSize),
		zap.String("network", config.Network),
		zap.String("ip_address", ip),
		zap.String("ssh_command", fmt.Sprintf("ssh -i <key> ubuntu@%s", ip)),
		zap.String("management_commands", "virsh shutdown/start/undefine"))

	// Attempt Consul registration (non-critical)
	if err := RegisterVMWithConsul(rc, config.Name, ip); err != nil {
		logger.Debug("Consul registration failed (non-critical)",
			zap.Error(err))
	}

	return nil
}

// CreateUbuntuVMWithConsul creates an Ubuntu VM with Consul agent pre-installed.
//
// This is the DEFAULT behavior for VM creation. Consul agent is deployed
// automatically to enable seamless service discovery.
//
// This function:
//  1. Generates base cloud-init (security hardening)
//  2. Generates Consul agent cloud-init
//  3. Merges both configurations intelligently
//  4. Creates VM with merged cloud-init
//  5. Waits for VM to boot
//  6. Consul agent auto-registers with cluster
//
// Graceful degradation:
//   - If Consul cloud-init generation fails → deploy VM without Consul (warn)
//   - If cloud-init merge fails → deploy VM with base config only (warn)
//   - If Consul servers unavailable → agent deploys with empty retry_join (warn)
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - vmName: Name for the VM
//
// Returns:
//   - error: Any VM creation error (Consul failures are non-fatal warnings)
//
// Example:
//
//	err := CreateUbuntuVMWithConsul(rc, "web-server-01")
//	// VM created with Consul agent for seamless service discovery
func CreateUbuntuVMWithConsul(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Ubuntu VM with Consul agent for seamless service discovery",
		zap.String("vm_name", vmName))

	// ASSESS - Generate base cloud-init (security hardening, SSH keys, qemu-guest-agent)
	baseCloudInit, err := generateBaseCloudInit(rc, vmName)
	if err != nil {
		return fmt.Errorf("failed to generate base cloud-init: %w", err)
	}

	// ASSESS - Generate Consul agent cloud-init
	consulCloudInit, err := EnableConsulAutoRegistrationForVM(rc, vmName)
	if err != nil {
		logger.Warn("Failed to generate Consul cloud-init, deploying VM without Consul agent",
			zap.Error(err),
			zap.String("vm_name", vmName),
			zap.String("impact", "VM will not auto-register with Consul cluster"),
			zap.String("remediation", "Manually install Consul or use --disable-consul to suppress this warning"))

		// Graceful degradation - create VM without Consul
		return CreateSimpleUbuntuVM(rc, vmName)
	}

	// INTERVENE - Merge cloud-init configs
	mergedCloudInit, err := MergeCloudInitConfigs(rc, baseCloudInit, consulCloudInit)
	if err != nil {
		logger.Warn("Failed to merge cloud-init configs, deploying with base config only",
			zap.Error(err),
			zap.String("vm_name", vmName))

		// Graceful degradation - create VM with base config
		return CreateSimpleUbuntuVM(rc, vmName)
	}

	// INTERVENE - Create VM with merged cloud-init
	if err := createVMWithMergedCloudInit(rc, vmName, mergedCloudInit); err != nil {
		return fmt.Errorf("failed to create VM with merged cloud-init: %w", err)
	}

	// EVALUATE - Report success
	logger.Info("VM created successfully with Consul agent",
		zap.String("vm_name", vmName),
		zap.String("consul_status", "agent will auto-register on first boot"),
		zap.String("service_discovery", "enabled"))

	return nil
}

// generateBaseCloudInit creates the base cloud-init configuration for a VM.
//
// This includes:
//   - Hostname configuration
//   - Ubuntu user with SSH keys
//   - Qemu guest agent installation
//   - Package updates
//   - SSH hardening (disable password auth, disable root)
//
// Parameters:
//   - rc: RuntimeContext
//   - vmName: VM name (used as hostname)
//
// Returns:
//   - string: Base cloud-init YAML
//   - error: Any generation error
func generateBaseCloudInit(rc *eos_io.RuntimeContext, vmName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Find existing SSH keys
	sshKeys := findSSHKeys()
	if len(sshKeys) == 0 {
		logger.Warn("No SSH keys found - VM will not be accessible via SSH",
			zap.String("remediation", "Place SSH public key in ~/.ssh/ before creating VMs"))
	}

	logger.Debug("Generating base cloud-init",
		zap.String("vm_name", vmName),
		zap.Int("ssh_key_count", len(sshKeys)))

	baseCloudInit := fmt.Sprintf(`#cloud-config
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
  - systemctl enable --now qemu-guest-agent

ssh_pwauth: false
disable_root: true
`, vmName, formatSSHKeys(sshKeys))

	return baseCloudInit, nil
}

// createVMWithMergedCloudInit creates a VM using the merged cloud-init configuration.
//
// This is similar to CreateSimpleUbuntuVM but uses a pre-generated cloud-init
// instead of generating it inline.
//
// Parameters:
//   - rc: RuntimeContext
//   - vmName: VM name
//   - cloudInit: Merged cloud-init YAML
//
// Returns:
//   - error: Any VM creation error
func createVMWithMergedCloudInit(rc *eos_io.RuntimeContext, vmName string, cloudInit string) error {
	// Lock entire VM creation to prevent race conditions
	vmCreationMutex.Lock()
	defer vmCreationMutex.Unlock()

	logger := otelzap.Ctx(rc.Ctx)

	// Check prerequisites
	logger.Info("Checking KVM/libvirt prerequisites...")
	if err := checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// Create VM configuration with defaults
	config := SimpleVMConfig{
		Name:     vmName,
		Memory:   "4096",
		VCPUs:    "2",
		DiskSize: "40",
		Network:  "default",
	}

	// Input validation
	if err := validateSimpleVMConfig(&config); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Clean up any existing domain with same name for idempotency
	logger.Info("Cleaning up potential domain conflicts", zap.String("vm_name", config.Name))
	cleanupExistingDomain(config.Name, &logger)

	// Create working directory
	seedDir := filepath.Join(isoDir, config.Name)
	if err := os.MkdirAll(seedDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create seed directory: %w", err)
	}

	logger.Info("Creating Ubuntu 24.04 VM with merged cloud-init", zap.String("name", config.Name))

	// Write merged cloud-init to user-data
	userDataPath := filepath.Join(seedDir, "user-data")
	if err := os.WriteFile(userDataPath, []byte(cloudInit), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write merged user-data: %w", err)
	}

	// Create meta-data
	metaData := fmt.Sprintf(`instance-id: %s
local-hostname: %s
`, config.Name, config.Name)

	metaDataPath := filepath.Join(seedDir, "meta-data")
	if err := os.WriteFile(metaDataPath, []byte(metaData), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write meta-data: %w", err)
	}

	// Generate seed.img
	seedImgPath := filepath.Join(seedDir, "seed.img")
	if err := generateSeedImage(seedDir, seedImgPath); err != nil {
		return fmt.Errorf("failed to generate seed image: %w", err)
	}

	// Download or copy base image
	baseImagePath := filepath.Join(isoDir, "ubuntu-24.04-base.img")
	if _, err := os.Stat(baseImagePath); os.IsNotExist(err) {
		logger.Info("Downloading Ubuntu base image")
		if err := downloadBaseImage(baseImagePath, &logger); err != nil {
			return fmt.Errorf("failed to get base image: %w", err)
		}
	} else {
		logger.Info("Using existing base image", zap.String("path", baseImagePath))
	}

	// Create VM disk from base
	vmDiskPath := filepath.Join(isoDir, config.Name+".qcow2")
	if err := createVMDisk(baseImagePath, vmDiskPath, config.DiskSize, &logger); err != nil {
		return fmt.Errorf("failed to create VM disk: %w", err)
	}

	// Launch VM with virt-install
	if err := launchVM(config, vmDiskPath, seedImgPath, &logger); err != nil {
		return fmt.Errorf("failed to launch VM: %w", err)
	}

	// Get VM IP
	ip, _ := waitForVMIP(config.Name, 30, &logger)

	logger.Info("VM created successfully with merged cloud-init",
		zap.String("name", config.Name),
		zap.String("ip", ip))

	// Attempt Consul registration (non-critical)
	if err := RegisterVMWithConsul(rc, config.Name, ip); err != nil {
		logger.Debug("Consul registration failed (non-critical)",
			zap.Error(err))
	}

	return nil
}

func checkPrerequisites() error {
	// Check required commands
	requiredCmds := []string{"virsh", "virt-install", "qemu-img", "cloud-localds", "wget"}
	for _, cmd := range requiredCmds {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("%s not found - install required packages", cmd)
		}
	}

	// Check if KVM is available
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("KVM not available - ensure virtualization is enabled in BIOS")
	}

	// Check if libvirt daemon is running
	if _, err := os.Stat("/var/run/libvirt/libvirt-sock"); err != nil {
		return fmt.Errorf("libvirt daemon not running - run: sudo systemctl start libvirtd")
	}

	// Ensure iso directory exists and is writable
	if err := os.MkdirAll(isoDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create iso directory: %w", err)
	}

	return nil
}

func validateSimpleVMConfig(config *SimpleVMConfig) error {
	// Validate VM name
	if config.Name != "" {
		validName := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-_]{0,63}$`)
		if !validName.MatchString(config.Name) {
			return fmt.Errorf("invalid VM name: must be alphanumeric with - or _")
		}
	}

	// Set defaults
	if config.Memory == "" {
		config.Memory = "4096"
	}
	if config.VCPUs == "" {
		config.VCPUs = "2"
	}
	if config.DiskSize == "" {
		config.DiskSize = "40"
	}
	if config.Network == "" {
		config.Network = "default"
	}

	return nil
}

func generateVMName() string {
	// Find next available number
	max := 0
	files, _ := filepath.Glob(filepath.Join(isoDir, vmPrefix+"-*"))
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasPrefix(base, vmPrefix+"-") {
			// Extract number
			suffix := strings.TrimPrefix(base, vmPrefix+"-")
			var num int
			_, _ = fmt.Sscanf(suffix, "%d", &num)
			if num > max {
				max = num
			}
		}
	}
	return fmt.Sprintf("%s-%03d", vmPrefix, max+1)
}

// getRealUserIDs returns the real user's UID and GID when running under sudo
// Returns (-1, -1) if not running under sudo or if values can't be determined
func getRealUserIDs() (uid int, gid int) {
	uid = -1
	gid = -1

	// Check if running under sudo
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")

	if sudoUID != "" {
		if parsedUID, err := strconv.Atoi(sudoUID); err == nil {
			uid = parsedUID
		}
	}

	if sudoGID != "" {
		if parsedGID, err := strconv.Atoi(sudoGID); err == nil {
			gid = parsedGID
		}
	}

	return uid, gid
}

func generateSSHKeyED25519(seedDir, vmName string) (string, string, error) {
	privKeyPath := filepath.Join(seedDir, fmt.Sprintf("id_ed25519_%s", vmName))

	// Generate ED25519 key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// Generate SSH public key first (we'll need this)
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create ssh public key: %w", err)
	}

	// Marshal private key in OpenSSH format using ssh package
	privKeyPEM, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write private key in OpenSSH format (PEM encoded)
	privKeyFile, err := os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to create private key file: %w", err)
	}
	defer func() { _ = privKeyFile.Close() }()

	if err := pem.Encode(privKeyFile, privKeyPEM); err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	// Get public key string
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))

	// Write public key
	pubKeyPath := privKeyPath + ".pub"
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyStr), shared.ConfigFilePerm); err != nil {
		return "", "", fmt.Errorf("failed to write public key: %w", err)
	}

	// Change ownership to real user if running under sudo
	uid, gid := getRealUserIDs()
	if uid != -1 && gid != -1 {
		// Change ownership of private key
		if err := os.Chown(privKeyPath, uid, gid); err != nil {
			return "", "", fmt.Errorf("failed to chown private key: %w", err)
		}
		// Change ownership of public key
		if err := os.Chown(pubKeyPath, uid, gid); err != nil {
			return "", "", fmt.Errorf("failed to chown public key: %w", err)
		}
	}

	return privKeyPath, strings.TrimSpace(pubKeyStr), nil
}

func findSSHKeys() []string {
	var keys []string
	var sshDirs []string

	// Check common SSH directories
	sshDirs = append(sshDirs, "/root/.ssh")
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		sshDirs = append(sshDirs, filepath.Join("/home", sudoUser, ".ssh"))
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		sshDirs = append(sshDirs, filepath.Join(homeDir, ".ssh"))
	}

	// Prefer ed25519 keys, then RSA
	keyPatterns := []string{"id_ed25519.pub", "id_rsa.pub", "*.pub"}

	for _, sshDir := range sshDirs {
		for _, pattern := range keyPatterns {
			matches, _ := filepath.Glob(filepath.Join(sshDir, pattern))
			for _, keyPath := range matches {
				if keyData, err := os.ReadFile(keyPath); err == nil {
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func createCloudInit(seedDir string, config SimpleVMConfig) error {
	// Create user-data
	userData := fmt.Sprintf(`#cloud-config
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
  - systemctl enable --now qemu-guest-agent

ssh_pwauth: false
disable_root: true
`, config.Name, formatSSHKeys(config.SSHKeys))

	userDataPath := filepath.Join(seedDir, "user-data")
	if err := os.WriteFile(userDataPath, []byte(userData), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write user-data: %w", err)
	}

	// Create meta-data
	metaData := fmt.Sprintf(`instance-id: %s
local-hostname: %s
`, config.Name, config.Name)

	metaDataPath := filepath.Join(seedDir, "meta-data")
	if err := os.WriteFile(metaDataPath, []byte(metaData), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write meta-data: %w", err)
	}

	return nil
}

func formatSSHKeys(keys []string) string {
	var formatted []string
	for _, key := range keys {
		formatted = append(formatted, "      - "+strings.TrimSpace(key))
	}
	return strings.Join(formatted, "\n")
}

func generateSeedImage(seedDir, outputPath string) error {
	// Use cloud-localds to create seed.img
	cmd := exec.Command("cloud-localds",
		outputPath,
		filepath.Join(seedDir, "user-data"),
		filepath.Join(seedDir, "meta-data"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cloud-localds failed: %w\nOutput: %s", err, output)
	}

	return nil
}

func downloadBaseImage(targetPath string, logger *otelzap.LoggerWithCtx) error {
	logger.Info("Downloading base image", zap.String("url", baseImageURL))

	// Use wget to download
	cmd := exec.Command("wget",
		"-O", targetPath,
		"--progress=dot:mega",
		baseImageURL)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wget failed: %w", err)
	}

	return nil
}

func createVMDisk(baseImagePath, vmDiskPath, diskSize string, logger *otelzap.LoggerWithCtx) error {
	logger.Info("Creating VM disk",
		zap.String("base", baseImagePath),
		zap.String("disk", vmDiskPath),
		zap.String("size", diskSize+"G"))

	// Create a copy-on-write clone with specified size
	cmd := exec.Command("qemu-img", "create",
		"-f", "qcow2",
		"-b", baseImagePath,
		"-F", "qcow2",
		vmDiskPath,
		diskSize+"G")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img failed: %w\nOutput: %s", err, output)
	}

	// Set proper permissions
	// SECURITY: VM disk images should not be world-readable (may contain sensitive data)
	if err := os.Chmod(vmDiskPath, shared.SecureConfigFilePerm); err != nil {
		logger.Warn("Failed to set disk permissions", zap.Error(err))
	}

	return nil
}

func launchVM(config SimpleVMConfig, diskPath, seedPath string, logger *otelzap.LoggerWithCtx) error {
	logger.Info("Launching VM with virt-install", zap.String("name", config.Name))

	args := []string{
		"--name", config.Name,
		"--memory", config.Memory,
		"--vcpus", config.VCPUs,
		"--disk", fmt.Sprintf("path=%s,format=qcow2", diskPath),
		"--disk", fmt.Sprintf("path=%s,device=cdrom", seedPath),
		"--os-variant", "ubuntu24.04",
		"--virt-type", "kvm",
		"--import",
		"--network", fmt.Sprintf("network=%s", config.Network),
		"--channel", "unix,target_type=virtio,name=org.qemu.guest_agent.0",
		"--graphics", "none",
		"--noautoconsole",
		"--autostart",
	}

	cmd := exec.Command("virt-install", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("virt-install failed: %w\nOutput: %s", err, output)
	}

	logger.Info("VM launched successfully", zap.String("name", config.Name))
	return nil
}

func waitForVMIP(vmName string, timeoutSecs int, logger *otelzap.LoggerWithCtx) (string, error) {
	logger.Info("Waiting for VM to get IP address", zap.String("vm", vmName))

	for i := 0; i < timeoutSecs; i++ {
		cmd := exec.Command("virsh", "domifaddr", vmName)
		output, _ := cmd.Output()

		// Parse output for IP
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "/") {
				fields := strings.Fields(line)
				for _, field := range fields {
					if strings.Contains(field, "/") {
						ip := strings.Split(field, "/")[0]
						logger.Info("VM IP address obtained", zap.String("ip", ip))
						return ip, nil
					}
				}
			}
		}

		time.Sleep(time.Second)
	}

	logger.Warn("Timeout waiting for VM IP", zap.String("vm", vmName))
	return "", fmt.Errorf("timeout waiting for IP")
}

func cleanupExistingDomain(vmName string, logger *otelzap.LoggerWithCtx) {
	ctx := context.Background()

	// Try to destroy (stop) the domain if it's running
	if err := DestroyDomain(ctx, vmName); err != nil {
		logger.Debug("Error destroying domain", zap.String("vm", vmName), zap.Error(err))
	} else {
		logger.Info("Stopped existing VM", zap.String("vm", vmName))
	}

	// Then undefine (remove) the domain completely
	if err := UndefineDomain(ctx, vmName, true); err != nil {
		logger.Debug("Error undefining domain", zap.String("vm", vmName), zap.Error(err))
	} else {
		logger.Info("Removed existing VM definition", zap.String("vm", vmName))
	}
}