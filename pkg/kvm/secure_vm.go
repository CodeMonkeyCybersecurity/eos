//go:build linux

// pkg/kvm/secure_vm.go

package kvm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecureVMConfig represents configuration for a security-hardened Ubuntu VM
type SecureVMConfig struct {
	Name           string
	Memory         string
	VCPUs          int
	DiskSize       string
	Network        string
	StoragePool    string
	SSHKeys        []string
	EnableTPM      bool
	SecureBoot     bool
	EncryptDisk    bool
	AutoUpdate     bool
	SecurityLevel  string // "basic", "moderate", "high", "paranoid"
	EnableFirewall bool
	EnableFail2ban bool
	EnableAudit    bool
	EnableAppArmor bool
	DisableIPv6    bool
}

// SecurityLevel represents the security configuration level
type SecurityLevel string

const (
	SecurityLevelBasic    SecurityLevel = "basic"
	SecurityLevelModerate SecurityLevel = "moderate"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelParanoid SecurityLevel = "paranoid"
)

// DefaultSecureVMConfig returns secure defaults for Ubuntu VMs
func DefaultSecureVMConfig(name string) *SecureVMConfig {
	return &SecureVMConfig{
		Name:           name,
		Memory:         "4GB",
		VCPUs:          2,
		DiskSize:       "40GB",
		Network:        "default",
		StoragePool:    "default",
		EnableTPM:      true,
		SecureBoot:     true,
		EncryptDisk:    true,
		AutoUpdate:     true,
		SecurityLevel:  string(SecurityLevelHigh), // Default to high security
		EnableFirewall: true,
		EnableFail2ban: true,
		EnableAudit:    true,
		EnableAppArmor: true,
		DisableIPv6:    true, // IPv6 disabled by default for security
	}
}

// ApplySecurityLevel configures security settings based on the selected level
func (c *SecureVMConfig) ApplySecurityLevel(level string) {
	switch SecurityLevel(level) {
	case SecurityLevelBasic:
		// Basic security - minimal hardening
		c.EnableTPM = false
		c.SecureBoot = false
		c.EncryptDisk = false
		c.EnableFail2ban = false
		c.EnableAudit = false
		c.EnableAppArmor = true // Keep AppArmor as it's Ubuntu default
		c.DisableIPv6 = false

	case SecurityLevelModerate:
		// Moderate security - reasonable defaults
		c.EnableTPM = false
		c.SecureBoot = true
		c.EncryptDisk = false
		c.EnableFail2ban = true
		c.EnableAudit = false
		c.EnableAppArmor = true
		c.DisableIPv6 = true

	case SecurityLevelHigh:
		// High security - comprehensive hardening
		c.EnableTPM = true
		c.SecureBoot = true
		c.EncryptDisk = true
		c.EnableFail2ban = true
		c.EnableAudit = true
		c.EnableAppArmor = true
		c.DisableIPv6 = true

	case SecurityLevelParanoid:
		// Paranoid security - maximum hardening
		c.EnableTPM = true
		c.SecureBoot = true
		c.EncryptDisk = true
		c.EnableFail2ban = true
		c.EnableAudit = true
		c.EnableAppArmor = true
		c.DisableIPv6 = true
		c.AutoUpdate = true
		c.EnableFirewall = true
	}

	c.SecurityLevel = level
}

// FindDefaultSSHKeys finds SSH public keys from common locations
func FindDefaultSSHKeys() ([]string, error) {
	var keys []string

	// First try to get the original user if running under sudo
	originalUser := os.Getenv("SUDO_USER")
	if originalUser == "" {
		originalUser = os.Getenv("USER")
	}

	// Common SSH key locations
	var sshDirs []string

	if originalUser != "" && originalUser != "root" {
		// Try the original user's home directory
		if originalUser == "root" {
			sshDirs = append(sshDirs, "/root/.ssh")
		} else {
			sshDirs = append(sshDirs, fmt.Sprintf("/home/%s/.ssh", originalUser))
		}
	}

	// Also check current user's directory as fallback
	if home := os.Getenv("HOME"); home != "" {
		sshDirs = append(sshDirs, filepath.Join(home, ".ssh"))
	}

	// Check each directory
	for _, sshDir := range sshDirs {
		if entries, err := os.ReadDir(sshDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pub") {
					keyPath := filepath.Join(sshDir, entry.Name())
					// Verify we can read the key
					if _, err := os.ReadFile(keyPath); err == nil {
						keys = append(keys, keyPath)
					}
				}
			}
		}
	}

	// Prefer Ed25519 keys over RSA for better security
	for i, key := range keys {
		if strings.Contains(key, "id_ed25519.pub") {
			// Move Ed25519 key to the front
			keys[0], keys[i] = keys[i], keys[0]
			break
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH public keys found. Please generate one with: ssh-keygen -t ed25519")
	}

	return keys, nil
}

// CreateSecureVM creates a security-hardened Ubuntu VM using Terraform
// NOTE: This function has been commented out as we've moved to direct virsh-based VM creation.
// The Terraform-based approach is still available in pkg/terraform/kvm if needed.
// TODO: Remove this commented code if the virsh-based approach proves sufficient
/*
func CreateSecureVM(ctx context.Context, manager *KVMManager, config *SecureVMConfig) (*VMInfo, error) {
	// Function body commented out - depends on Terraform types
}
*/

// ValidateSecureVMConfig validates the VM configuration
func ValidateSecureVMConfig(config *SecureVMConfig) error {
	if config.Name == "" {
		return fmt.Errorf("VM name is required")
	}

	// Validate memory
	if _, err := ParseMemorySize(config.Memory); err != nil {
		return fmt.Errorf("invalid memory size: %w", err)
	}

	// Validate disk size
	if _, err := ParseDiskSize(config.DiskSize); err != nil {
		return fmt.Errorf("invalid disk size: %w", err)
	}

	// Validate vCPUs
	if config.VCPUs < 1 || config.VCPUs > 64 {
		return fmt.Errorf("vCPUs must be between 1 and 64")
	}

	// Validate security level
	validLevels := map[string]bool{
		"basic":    true,
		"moderate": true,
		"high":     true,
		"paranoid": true,
	}

	if !validLevels[config.SecurityLevel] {
		return fmt.Errorf("invalid security level: %s (must be basic, moderate, high, or paranoid)", config.SecurityLevel)
	}

	return nil
}

// GetSecurityRecommendations returns security recommendations based on the configuration
func GetSecurityRecommendations(config *SecureVMConfig) []string {
	recommendations := []string{
		"Change the default password after first login",
		"Review security updates: 'sudo apt update && sudo apt list --upgradable'",
	}

	if config.EnableFirewall {
		recommendations = append(recommendations, "Enable UFW firewall: 'sudo ufw enable'")
	}

	if config.SecurityLevel != "paranoid" {
		recommendations = append(recommendations, "Consider upgrading to 'paranoid' security level for maximum protection")
	}

	if !config.EncryptDisk {
		recommendations = append(recommendations, "Consider enabling disk encryption for data at rest protection")
	}

	if !config.EnableAudit {
		recommendations = append(recommendations, "Consider enabling audit logging for security monitoring")
	}

	return recommendations
}
