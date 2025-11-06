package sizing

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreflightCheck(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := eos_io.NewContext(ctx, "test")

	// Test with minimal services
	services := []ServiceType{
		ServiceTypeWebServer,
		ServiceTypeDatabase,
	}

	// Use small workload profile
	workload := DefaultWorkloadProfiles["small"]

	// Run preflight check (should pass on most systems)
	err := PreflightCheck(rc, services, workload)

	// We don't assert no error because it depends on the test machine's resources
	// Instead, we just verify the function runs without panic
	if err != nil {
		t.Logf("PreflightCheck returned expected error on test machine: %v", err)
	}
}

func TestPostflightValidation(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := eos_io.NewContext(ctx, "test")

	// Test with services that might not be running
	services := []ServiceType{
		ServiceTypeWebServer,
		ServiceTypeDatabase,
	}

	// Run postflight validation
	err := PostflightValidation(rc, services)

	// We expect this to return an error since the services aren't actually deployed
	// but we verify it runs without panic
	if err != nil {
		t.Logf("PostflightValidation returned expected error: %v", err)
	}
}

func TestSystemResourceDetection(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := eos_io.NewContext(ctx, "test")

	// Test system resource detection
	resources, err := getSystemResources(rc)
	require.NoError(t, err)

	// Verify we got reasonable values
	assert.Greater(t, resources.CPU.Cores, float64(0))
	assert.Greater(t, resources.Memory.GB, float64(0))
	assert.Greater(t, resources.Disk.GB, float64(0))

	// Verify disk type detection
	assert.Contains(t, []string{"ssd", "hdd", "nvme"}, resources.Disk.Type)

	t.Logf("Detected system resources: CPU=%.1f cores, Memory=%.1f GB, Disk=%.1f GB (%s)",
		resources.CPU.Cores, resources.Memory.GB, resources.Disk.GB, resources.Disk.Type)
}

func TestMetricsCollection(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := eos_io.NewContext(ctx, "test")

	// Test metrics collection
	metrics, err := collectSystemMetrics(rc)
	require.NoError(t, err)

	// Verify we got reasonable values
	assert.GreaterOrEqual(t, metrics.CPUUsage, float64(0))
	assert.LessOrEqual(t, metrics.CPUUsage, float64(100))

	assert.GreaterOrEqual(t, metrics.MemoryUsage, float64(0))
	assert.LessOrEqual(t, metrics.MemoryUsage, float64(100))

	assert.GreaterOrEqual(t, metrics.LoadAverage, float64(0))

	t.Logf("Current system metrics: CPU=%.1f%%, Memory=%.1f%%, Load=%.2f",
		metrics.CPUUsage, metrics.MemoryUsage, metrics.LoadAverage)
}
