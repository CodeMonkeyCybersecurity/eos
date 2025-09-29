package kvm

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateTerraformHCL tests HCL generation without heredocs
func TestGenerateTerraformHCL(t *testing.T) {
	// Create test manager with minimal setup
	km := &KVMManager{
		workingDir: "/tmp/test",
	}

	// Test configuration
	config := &VMConfig{
		Name:        "test-vm",
		Memory:      4096,
		VCPUs:       2,
		DiskSize:    10737418240, // 10GB
		NetworkName: "default",
		StoragePool: "default",
		AutoStart:   true,
		EnableTPM:   false,
		SecureBoot:  false,
	}

	// Generate HCL with file paths
	userDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "user-data.yaml")
	metaDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "meta-data.yaml")

	hcl := km.generateTerraformHCL(config, userDataPath, metaDataPath)

	// Verify no heredocs are present
	if strings.Contains(hcl, "<<EOF") || strings.Contains(hcl, "<<-EOF") {
		t.Errorf("HCL should not contain heredoc markers:\n%s", hcl)
	}

	// Verify file() functions are used
	if !strings.Contains(hcl, "user_data = file(") {
		t.Errorf("HCL should use file() function for user_data")
	}

	if !strings.Contains(hcl, "meta_data = file(") {
		t.Errorf("HCL should use file() function for meta_data")
	}

	// Verify resource blocks
	if !strings.Contains(hcl, `resource "libvirt_cloudinit_disk" "test-vm_cloudinit"`) {
		t.Errorf("HCL should contain cloudinit disk resource")
	}

	if !strings.Contains(hcl, `resource "libvirt_volume" "test-vm_disk"`) {
		t.Errorf("HCL should contain volume resource")
	}

	if !strings.Contains(hcl, `resource "libvirt_domain" "test-vm"`) {
		t.Errorf("HCL should contain domain resource")
	}

	// Verify paths are included
	if !strings.Contains(hcl, userDataPath) {
		t.Errorf("HCL should contain user data path: %s", userDataPath)
	}

	if !strings.Contains(hcl, metaDataPath) {
		t.Errorf("HCL should contain meta data path: %s", metaDataPath)
	}

	t.Logf("Generated HCL successfully without heredocs")
}

// TestGenerateTerraformHCLWithSecurity tests HCL generation with security features
func TestGenerateTerraformHCLWithSecurity(t *testing.T) {
	// Create test manager
	km := &KVMManager{
		workingDir: "/tmp/test",
	}

	// Test configuration with security features
	config := &VMConfig{
		Name:          "secure-vm",
		Memory:        8192,
		VCPUs:         4,
		DiskSize:      21474836480, // 20GB
		NetworkName:   "default",
		StoragePool:   "default",
		AutoStart:     false,
		EnableTPM:     true,
		SecureBoot:    true,
		TPMBackend:    "emulator",
		TPMVersion:    "2.0",
		Firmware:      "/usr/share/OVMF/OVMF_CODE.fd",
		NVRAM:         "/usr/share/OVMF/OVMF_VARS.fd",
		EncryptDisk:   true,
		EncryptionKey: "test-key",
	}

	// Generate HCL
	userDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "user-data.yaml")
	metaDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "meta-data.yaml")

	hcl := km.generateTerraformHCL(config, userDataPath, metaDataPath)

	// Verify TPM configuration
	if !strings.Contains(hcl, "tpm {") {
		t.Errorf("HCL should contain TPM configuration")
	}

	if !strings.Contains(hcl, `backend_type    = "emulator"`) {
		t.Errorf("HCL should contain TPM backend type")
	}

	if !strings.Contains(hcl, `backend_version = "2.0"`) {
		t.Errorf("HCL should contain TPM version")
	}

	// Verify Secure Boot configuration
	if !strings.Contains(hcl, `firmware = "/usr/share/OVMF/OVMF_CODE.fd"`) {
		t.Errorf("HCL should contain firmware configuration")
	}

	if !strings.Contains(hcl, "nvram {") {
		t.Errorf("HCL should contain NVRAM configuration")
	}

	// Verify disk encryption
	if !strings.Contains(hcl, "encryption {") {
		t.Errorf("HCL should contain encryption block")
	}

	if !strings.Contains(hcl, `secret = "test-key"`) {
		t.Errorf("HCL should contain encryption key")
	}

	// Verify no heredocs
	if strings.Contains(hcl, "<<EOF") || strings.Contains(hcl, "<<-EOF") {
		t.Errorf("Secure HCL should not contain heredoc markers")
	}

	t.Logf("Generated secure HCL successfully without heredocs")
}

// TestGenerateTerraformHCLWithVolumes tests HCL generation with additional volumes
func TestGenerateTerraformHCLWithVolumes(t *testing.T) {
	// Create test manager
	km := &KVMManager{
		workingDir: "/tmp/test",
	}

	// Test configuration with additional volumes
	config := &VMConfig{
		Name:        "vm-with-volumes",
		Memory:      4096,
		VCPUs:       2,
		DiskSize:    10737418240, // 10GB
		NetworkName: "default",
		StoragePool: "default",
		Volumes: []VolumeConfig{
			{
				Name:   "data",
				Size:   53687091200, // 50GB
				Format: "qcow2",
				Pool:   "default",
			},
			{
				Name:   "backup",
				Size:   107374182400, // 100GB
				Format: "raw",
				Pool:   "backup-pool",
			},
		},
		AutoStart: true,
	}

	// Generate HCL
	userDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "user-data.yaml")
	metaDataPath := filepath.Join(km.workingDir, "cloud-init", config.Name, "meta-data.yaml")

	hcl := km.generateTerraformHCL(config, userDataPath, metaDataPath)

	// Verify additional volumes
	if !strings.Contains(hcl, `resource "libvirt_volume" "vm-with-volumes_volume_0"`) {
		t.Errorf("HCL should contain first additional volume")
	}

	if !strings.Contains(hcl, `resource "libvirt_volume" "vm-with-volumes_volume_1"`) {
		t.Errorf("HCL should contain second additional volume")
	}

	if !strings.Contains(hcl, `name   = "vm-with-volumes-data.qcow2"`) {
		t.Errorf("HCL should contain first volume name")
	}

	if !strings.Contains(hcl, `name   = "vm-with-volumes-backup.raw"`) {
		t.Errorf("HCL should contain second volume name")
	}

	// Verify volume attachments in domain
	if !strings.Contains(hcl, `volume_id = libvirt_volume.vm-with-volumes_volume_0.id`) {
		t.Errorf("HCL should reference first additional volume in domain")
	}

	if !strings.Contains(hcl, `volume_id = libvirt_volume.vm-with-volumes_volume_1.id`) {
		t.Errorf("HCL should reference second additional volume in domain")
	}

	t.Logf("Generated HCL with volumes successfully without heredocs")
}