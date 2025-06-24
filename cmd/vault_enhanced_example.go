// Example command showing enhanced vault container usage
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	vaultpkg "github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// _vaultEnhancedCmd demonstrates the enhanced vault container usage
// Prefixed with underscore to indicate it's intentionally unused (example/demo code)
//
//nolint:unused
var _vaultEnhancedCmd = &cobra.Command{
	Use:   "vault-enhanced",
	Short: "Example command using enhanced vault container",
	Long: `Demonstrates how to use the enhanced vault container with:
- Proper lifecycle management
- Health monitoring
- Graceful error handling
- Structured logging`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return eos_cli.Wrap(_vaultEnhancedExample)(cmd, args)
	},
}

// _vaultEnhancedExample shows enhanced vault container usage patterns
// Prefixed with underscore to indicate it's intentionally unused (example/demo code)
//
//nolint:unused
func _vaultEnhancedExample(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := rc.Log.Named("vault.enhanced.example")

	logger.Info(" Starting enhanced vault container example")

	// Create enhanced vault container
	vaultContainer, err := vaultpkg.NewEnhancedVaultContainer(rc)
	if err != nil {
		logger.Error(" Failed to create enhanced vault container", zap.Error(err))
		return fmt.Errorf("failed to create vault container: %w", err)
	}

	// Start the container (initializes all services)
	if err := vaultContainer.Start(); err != nil {
		logger.Error(" Failed to start vault container", zap.Error(err))
		return fmt.Errorf("failed to start vault container: %w", err)
	}

	// Ensure proper cleanup
	defer func() {
		if err := vaultContainer.Stop(); err != nil {
			logger.Error(" Failed to stop vault container", zap.Error(err))
		}
	}()

	logger.Info(" Enhanced vault container started successfully")

	// Perform health check
	if err := vaultContainer.Health(); err != nil {
		logger.Warn("Vault container health check failed", zap.Error(err))
		// Continue with degraded functionality
	} else {
		logger.Info("💚 Vault container health check passed")
	}

	// Get vault service with type safety
	vaultService, err := vaultContainer.GetVaultService()
	if err != nil {
		logger.Error(" Failed to get vault service", zap.Error(err))
		return fmt.Errorf("failed to get vault service: %w", err)
	}

	// Get secret store for direct operations
	secretStore, err := vaultContainer.GetSecretStore()
	if err != nil {
		logger.Error(" Failed to get secret store", zap.Error(err))
		return fmt.Errorf("failed to get secret store: %w", err)
	}

	// Example 1: Test secret operations with timeout
	if err := _demonstrateSecretOperations(rc, secretStore, logger); err != nil {
		logger.Error(" Secret operations demonstration failed", zap.Error(err))
		return err
	}

	// Example 2: Show service-level operations
	if err := _demonstrateServiceOperations(rc, vaultService, logger); err != nil {
		logger.Error(" Service operations demonstration failed", zap.Error(err))
		return err
	}

	// Example 3: Demonstrate error handling and fallback
	if err := _demonstrateErrorHandling(rc, secretStore, logger); err != nil {
		logger.Error(" Error handling demonstration failed", zap.Error(err))
		return err
	}

	logger.Info(" Enhanced vault container example completed successfully")
	return nil
}

// _demonstrateSecretOperations shows secret store operations with proper error handling
// Prefixed with underscore to indicate it's intentionally unused (example/demo code)
//
//nolint:unused
func _demonstrateSecretOperations(rc *eos_io.RuntimeContext, secretStore vault.SecretStore, logger *zap.Logger) error {
	logger.Info(" Demonstrating secret operations")

	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	// Test secret key
	testKey := "example/demo-secret"
	testValue := fmt.Sprintf("demo-value-%d", time.Now().Unix())

	// Create a test secret
	secret := &vault.Secret{
		Key:       testKey,
		Value:     testValue,
		Metadata:  map[string]string{"demo": "true", "created_by": "enhanced_example"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set secret with timeout
	logger.Info(" Setting test secret", zap.String("key", testKey))
	if err := secretStore.Set(ctx, testKey, secret); err != nil {
		logger.Warn("Failed to set secret (may be in fallback mode)", zap.Error(err))
		// Don't fail completely - this might be expected in fallback mode
	} else {
		logger.Info(" Secret set successfully")
	}

	// Read secret back
	logger.Info(" Reading test secret", zap.String("key", testKey))
	retrievedSecret, err := secretStore.Get(ctx, testKey)
	if err != nil {
		logger.Warn("Failed to read secret", zap.Error(err))
	} else {
		logger.Info(" Secret retrieved successfully",
			zap.String("key", retrievedSecret.Key),
			zap.Any("metadata", retrievedSecret.Metadata),
		)
	}

	// List secrets with prefix
	logger.Info(" Listing secrets with prefix", zap.String("prefix", "example/"))
	secrets, err := secretStore.List(ctx, "example/")
	if err != nil {
		logger.Warn("Failed to list secrets", zap.Error(err))
	} else {
		logger.Info(" Secrets listed successfully", zap.Int("count", len(secrets)))
	}

	// Clean up test secret
	logger.Info("🗑️ Cleaning up test secret", zap.String("key", testKey))
	if err := secretStore.Delete(ctx, testKey); err != nil {
		logger.Warn("Failed to delete test secret", zap.Error(err))
	} else {
		logger.Info(" Test secret deleted successfully")
	}

	return nil
}

// _demonstrateServiceOperations shows domain service level operations
// Prefixed with underscore to indicate it's intentionally unused (example/demo code)
//
//nolint:unused
func _demonstrateServiceOperations(_ *eos_io.RuntimeContext, vaultService *vault.Service, logger *zap.Logger) error {
	logger.Info(" Demonstrating service-level operations")

	if vaultService == nil {
		logger.Info(" Vault service not available (running in fallback mode)")
		return nil
	}

	// TODO: Implement service-level operations when domain service methods are available
	// This would include operations like:
	// - vaultService.GetSecretWithAudit(ctx, userID, key)
	// - vaultService.CreateSecretWithValidation(ctx, userID, secret)
	// - vaultService.RotateSecret(ctx, userID, key)

	logger.Info(" Service-level operations will be implemented when domain service methods are available")
	return nil
}

// _demonstrateErrorHandling shows proper error handling patterns
// Prefixed with underscore to indicate it's intentionally unused (example/demo code)
//
//nolint:unused
func _demonstrateErrorHandling(rc *eos_io.RuntimeContext, secretStore vault.SecretStore, logger *zap.Logger) error {
	logger.Info("🚨 Demonstrating error handling and fallback behavior")

	// Create context with very short timeout to trigger timeout errors
	ctx, cancel := context.WithTimeout(rc.Ctx, 1*time.Millisecond)
	defer cancel()

	// This should timeout and demonstrate error handling
	_, err := secretStore.Get(ctx, "timeout-test")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Info(" Timeout error handled correctly", zap.Error(err))
		} else {
			logger.Info(" Other error occurred (expected in fallback mode)", zap.Error(err))
		}
	}

	// Test with invalid secret key
	invalidSecret := &vault.Secret{
		Key:   "", // Invalid empty key
		Value: "test",
	}

	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel2()

	err = secretStore.Set(ctx2, "", invalidSecret)
	if err != nil {
		logger.Info(" Invalid secret rejected correctly", zap.Error(err))
	}

	logger.Info(" Error handling demonstration completed")
	return nil
}

// Integration with existing command structure
func init() {
	// This would be added to the appropriate parent command
	// For example: rootCmd.AddCommand(vaultEnhancedCmd)
}

// MigrateExistingVaultCommand shows how to migrate an existing vault command
func MigrateExistingVaultCommand() {
	// Example of how to update an existing command to use enhanced container

	// OLD PATTERN:
	oldVaultCommand := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Direct vault package calls - OLD PATTERN EXAMPLE
		// This shows what the old pattern looked like
		_ = rc // Use context
		return fmt.Errorf("old pattern example - not actually executed")
	}

	// NEW PATTERN:
	newVaultCommand := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Create enhanced container
		vaultContainer, err := vaultpkg.NewEnhancedVaultContainer(rc)
		if err != nil {
			return fmt.Errorf("failed to create vault container: %w", err)
		}

		// Start container
		if err := vaultContainer.Start(); err != nil {
			return fmt.Errorf("failed to start vault container: %w", err)
		}
		defer func() {
			if err := vaultContainer.Stop(); err != nil {
				rc.Log.Named("vault.enhanced.example").Error("Failed to stop vault container", zap.Error(err))
			}
		}()

		// Get services with type safety
		vaultService, err := vaultContainer.GetVaultService()
		if err != nil {
			return fmt.Errorf("failed to get vault service: %w", err)
		}

		// Use service for operations
		_ = vaultService
		return nil
	}

	// Show the pattern without actually calling the functions
	_ = oldVaultCommand
	_ = newVaultCommand
}
