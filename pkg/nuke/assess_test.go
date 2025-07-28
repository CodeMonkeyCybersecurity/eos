package nuke

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicServiceDiscovery(t *testing.T) {
	// Test that dynamic service discovery returns services
	excluded := make(map[string]bool)
	services := getRemovableServicesDynamic(excluded)
	
	// Should have services from various components
	assert.NotEmpty(t, services, "Should have discovered services")
	
	// Check for known services
	serviceMap := make(map[string]bool)
	for _, svc := range services {
		serviceMap[svc.Name] = true
	}
	
	// These services should be discovered
	expectedServices := []string{
		"osqueryd",      // from osquery
		"boundary",      // from boundary
		"docker",        // from docker
		"eos-storage-monitor", // from eos
		"nomad",         // hardcoded but valid
		"consul",        // hardcoded but valid
		"vault",         // hardcoded but valid
	}
	
	for _, expected := range expectedServices {
		assert.True(t, serviceMap[expected], "Should have discovered %s service", expected)
	}
}

func TestDynamicDirectoryDiscovery(t *testing.T) {
	// Test that dynamic directory discovery returns directories
	excluded := make(map[string]bool)
	keepData := false
	directories := getRemovableDirectoriesDynamic(excluded, keepData)
	
	// Should have directories from various components
	assert.NotEmpty(t, directories, "Should have discovered directories")
	
	// Check for known directories
	dirMap := make(map[string]bool)
	for _, dir := range directories {
		dirMap[dir.Path] = true
	}
	
	// These directories should be discovered
	expectedDirs := []string{
		"/etc/osquery",       // from osquery
		"/etc/boundary.d",    // from boundary
		"/var/lib/docker",    // from docker
		"/var/lib/eos",       // from eos
		"/srv/salt",          // hardcoded but valid
		"/opt/vault",         // hardcoded but valid
		"/opt/nomad",         // hardcoded but valid
		"/opt/consul",        // hardcoded but valid
	}
	
	for _, expected := range expectedDirs {
		assert.True(t, dirMap[expected], "Should have discovered %s directory", expected)
	}
}

func TestExclusionLogic(t *testing.T) {
	// Test that exclusion works properly
	excluded := map[string]bool{
		"docker": true,
		"osquery": true,
	}
	
	services := getRemovableServicesDynamic(excluded)
	
	// Should not have docker or osquery services
	for _, svc := range services {
		assert.NotEqual(t, "docker", svc.Component, "Docker should be excluded")
		assert.NotEqual(t, "osquery", svc.Component, "Osquery should be excluded")
		assert.NotEqual(t, "osqueryd", svc.Name, "Osqueryd service should be excluded")
	}
}

func TestKeepDataLogic(t *testing.T) {
	// Test that keepData works properly
	excluded := make(map[string]bool)
	keepData := true
	directories := getRemovableDirectoriesDynamic(excluded, keepData)
	
	// Should not have any data directories
	for _, dir := range directories {
		assert.False(t, dir.IsData, "Should not include data directories when keepData is true: %s", dir.Path)
	}
}

func TestAssessInfrastructure(t *testing.T) {
	// Test the main assess function
	rc := &eos_io.RuntimeContext{}
	config := &Config{
		ExcludeList: []string{"docker"},
		DevMode:     false,
		KeepData:    false,
	}
	
	plan, err := AssessInfrastructure(rc, config)
	require.NoError(t, err, "AssessInfrastructure should not error")
	
	assert.NotNil(t, plan, "Should return a removal plan")
	assert.NotEmpty(t, plan.Services, "Should have services to remove")
	assert.NotEmpty(t, plan.Directories, "Should have directories to remove")
	assert.Contains(t, plan.ExcludedItems, "docker", "Should include docker in excluded items")
}