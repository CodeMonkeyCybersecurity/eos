// pkg/terraform/kvm/exec_manager_test.go

package kvm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecManager_Creation(t *testing.T) {
	// Skip if terraform is not available
	if _, err := os.Stat("/usr/bin/terraform"); os.IsNotExist(err) {
		t.Skip("Terraform not installed, skipping test")
	}

	rc := testutil.TestContext(t)
	tmpDir := t.TempDir()
	logger := testutil.TestLogger(t)

	em, err := NewExecManager(rc.Ctx, tmpDir, logger)
	assert.NoError(t, err)
	assert.NotNil(t, em)
	assert.Equal(t, tmpDir, em.workingDir)
}

func TestExecManager_GenerateInMemoryConfig(t *testing.T) {
	rc := testutil.TestContext(t)
	tmpDir := t.TempDir()
	logger := testutil.TestLogger(t)

	// Create ExecManager manually without terraform binary requirement
	em := &ExecManager{
		workingDir: tmpDir,
		logger:     logger,
		ctx:        rc.Ctx,
	}

	config := &VMConfig{
		Name:        "test-vm",
		Memory:      4096,
		VCPUs:       2,
		DiskSize:    10737418240, // 10GB
		NetworkName: "default",
		StoragePool: "default",
		UserData:    "#cloud-config\npackage_update: true",
		MetaData:    "",
	}

	// Generate configuration
	jsonConfig, err := em.generateInMemoryConfig(config)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonConfig)

	// Verify cloud-init files were created
	cloudInitDir := filepath.Join(tmpDir, "cloud-init", config.Name)
	assert.DirExists(t, cloudInitDir)

	userDataPath := filepath.Join(cloudInitDir, "user-data.yaml")
	assert.FileExists(t, userDataPath)

	metaDataPath := filepath.Join(cloudInitDir, "meta-data.yaml")
	assert.FileExists(t, metaDataPath)

	// Verify JSON contains expected content
	jsonStr := string(jsonConfig)
	assert.Contains(t, jsonStr, "libvirt_cloudinit_disk")
	assert.Contains(t, jsonStr, "libvirt_volume")
	assert.Contains(t, jsonStr, "libvirt_domain")
	assert.Contains(t, jsonStr, "test-vm")
}

func TestExecManager_GetVMState_NotFound(t *testing.T) {
	rc := testutil.TestContext(t)
	tmpDir := t.TempDir()
	logger := testutil.TestLogger(t)

	em := &ExecManager{
		workingDir: tmpDir,
		logger:     logger,
		ctx:        rc.Ctx,
	}

	// This should fail gracefully when VM doesn't exist
	state, err := em.GetVMState("non-existent-vm")
	assert.Error(t, err)
	assert.Nil(t, state)
	assert.Contains(t, err.Error(), "not found")
}
