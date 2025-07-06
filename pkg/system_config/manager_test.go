// pkg/system_config/manager_test.go
package system_config

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestSystemConfigManagerCreation(t *testing.T) {
	scm := NewSystemConfigManager()
	if scm == nil {
		t.Fatal("Failed to create SystemConfigManager")
	}

	if scm.managers == nil {
		t.Fatal("Managers map not initialized")
	}
}

func TestSystemConfigManagerRegistration(t *testing.T) {
	scm := NewSystemConfigManager()
	
	// Create a test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := eos_io.NewContext(ctx, "test")

	// Create a test manager
	config := &SystemToolsConfig{
		UpdateSystem:    false, // Don't actually update in tests
		InstallPackages: false, // Don't actually install in tests
		Interactive:     false,
	}
	manager := NewSystemToolsManager(rc, config)

	// Register the manager
	scm.RegisterManager(ConfigTypeSystemTools, manager)

	// Verify registration
	retrievedManager, err := scm.GetManager(ConfigTypeSystemTools)
	if err != nil {
		t.Fatalf("Failed to retrieve registered manager: %v", err)
	}

	if retrievedManager == nil {
		t.Fatal("Retrieved manager is nil")
	}

	if retrievedManager.GetType() != ConfigTypeSystemTools {
		t.Fatalf("Expected type %s, got %s", ConfigTypeSystemTools, retrievedManager.GetType())
	}
}

func TestSystemConfigManagerUnregisteredType(t *testing.T) {
	scm := NewSystemConfigManager()

	_, err := scm.GetManager(ConfigTypeMFA)
	if err == nil {
		t.Fatal("Expected error for unregistered configuration type")
	}
}

func TestListAvailableConfigurations(t *testing.T) {
	scm := NewSystemConfigManager()
	
	// Initially should be empty
	configs := scm.ListAvailableConfigurations()
	if len(configs) != 0 {
		t.Fatalf("Expected 0 configurations, got %d", len(configs))
	}

	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := eos_io.NewContext(ctx, "test")

	// Register a manager
	config := &SystemToolsConfig{
		UpdateSystem:    false,
		InstallPackages: false,
		Interactive:     false,
	}
	manager := NewSystemToolsManager(rc, config)
	scm.RegisterManager(ConfigTypeSystemTools, manager)

	// Now should have one
	configs = scm.ListAvailableConfigurations()
	if len(configs) != 1 {
		t.Fatalf("Expected 1 configuration, got %d", len(configs))
	}

	if configs[0] != ConfigTypeSystemTools {
		t.Fatalf("Expected %s, got %s", ConfigTypeSystemTools, configs[0])
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test CheckFileExists
	if CheckFileExists("/nonexistent/file") {
		t.Error("CheckFileExists should return false for nonexistent file")
	}

	// Test ValidateEmail
	validEmails := []string{
		"test@example.com",
		"user.name@domain.org",
		"admin@test-domain.net",
	}

	for _, email := range validEmails {
		if err := ValidateEmail(email); err != nil {
			t.Errorf("Valid email %s failed validation: %v", email, err)
		}
	}

	invalidEmails := []string{
		"",
		"invalid",
		"@domain.com",
		"user@",
		"user.domain.com",
	}

	for _, email := range invalidEmails {
		if err := ValidateEmail(email); err == nil {
			t.Errorf("Invalid email %s passed validation", email)
		}
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("Failed to generate secure token: %v", err)
	}

	if len(token) != 32 {
		t.Fatalf("Expected token length 32, got %d", len(token))
	}

	// Generate another token and ensure they're different
	token2, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("Failed to generate second secure token: %v", err)
	}

	if token == token2 {
		t.Error("Generated tokens should be different")
	}
}

// Benchmark tests
func BenchmarkGenerateSecureToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(32)
		if err != nil {
			b.Fatalf("Failed to generate token: %v", err)
		}
	}
}

func BenchmarkValidateEmail(b *testing.B) {
	email := "test@example.com"
	for i := 0; i < b.N; i++ {
		ValidateEmail(email)
	}
}