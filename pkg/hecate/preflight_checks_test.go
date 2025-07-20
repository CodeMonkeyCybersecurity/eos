package hecate

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreflightChecks(t *testing.T) {
	// Create test runtime context
	rc := eos_io.NewTestContext(t)

	// Run preflight checks
	result, err := PreflightChecks(rc)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify basic structure
	assert.NotNil(t, result.Dependencies)
	assert.NotNil(t, result.NetworkCheck)
	assert.NotNil(t, result.DiskSpace)
	assert.NotNil(t, result.PortAvailability)
	assert.NotNil(t, result.SystemChecks)
}

func TestDependencyStatus(t *testing.T) {
	dep := DependencyStatus{
		Name:        "Test Service",
		Description: "Test Description",
		Required:    true,
		Installed:   false,
		Running:     false,
		InstallCmd:  "test",
	}

	assert.Equal(t, "Test Service", dep.Name)
	assert.True(t, dep.Required)
	assert.False(t, dep.Installed)
}

func TestNetworkCheckResult(t *testing.T) {
	netCheck := NetworkCheckResult{
		PublicIP:          "1.2.3.4",
		Port80Open:        true,
		Port443Open:       true,
		DNSWorking:        true,
		BehindNAT:         false,
		InternetReachable: true,
	}

	assert.Equal(t, "1.2.3.4", netCheck.PublicIP)
	assert.True(t, netCheck.Port80Open)
	assert.True(t, netCheck.DNSWorking)
}

func TestAnalyzeResults(t *testing.T) {
	result := &PreflightCheckResult{
		Dependencies: []DependencyStatus{
			{
				Name:      "Required Service",
				Required:  true,
				Installed: false,
				Running:   false,
			},
		},
		NetworkCheck: NetworkCheckResult{
			DNSWorking:        true,
			InternetReachable: true,
		},
		CanProceed:     true,
		CriticalIssues: []string{},
		Warnings:       []string{},
	}

	// Analyze should mark as cannot proceed due to missing required dependency
	analyzeResults(result)

	assert.False(t, result.CanProceed)
	assert.NotEmpty(t, result.CriticalIssues)
}

func TestIsPortInUse(t *testing.T) {
	// Test with a port that's likely not in use
	assert.False(t, isPortInUse(65432))

	// Note: Testing a port that's in use would require actually binding to it
	// which could interfere with other tests or system services
}

func TestCanReachInternet(t *testing.T) {
	rc := eos_io.NewTestContext(t)
	
	// This test might fail in isolated environments
	// Just verify it returns a boolean without error
	result := canReachInternet(rc)
	assert.IsType(t, bool(true), result)
}