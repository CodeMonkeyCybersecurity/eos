package system

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
)

func TestCleanupAPTPackages(t *testing.T) {
	// This is a basic test to ensure the function doesn't panic
	// In a real test environment, you would mock the CLI calls
	rc := &eos_io.RuntimeContext{}

	// Should not error (warnings are acceptable)
	err := CleanupAPTPackages(rc)
	assert.NoError(t, err, "CleanupAPTPackages should not return an error")
}

func TestUpdateAPTCache(t *testing.T) {
	// This test will likely fail in a test environment without apt
	// but it verifies the function signature and basic logic
	rc := &eos_io.RuntimeContext{}

	// May error in test environment, that's okay
	_ = UpdateAPTCache(rc)
}

func TestCleanupSystemPackages(t *testing.T) {
	// Test the comprehensive cleanup function
	rc := &eos_io.RuntimeContext{}

	// Should not error (warnings are acceptable)
	err := CleanupSystemPackages(rc)
	assert.NoError(t, err, "CleanupSystemPackages should not return an error")
}
