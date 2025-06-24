// Package architecture - Migration Guide and Examples
package architecture

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// This file demonstrates how to migrate existing Eos code to the clean architecture

// BEFORE: Tightly coupled code with direct dependencies
// This is how current Eos code typically looks

/*
//  PROBLEMATIC: Direct dependencies, no interfaces, mixed concerns
func OldVaultOperations(rc *eos_io.RuntimeContext) error {
	// Direct vault client creation
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return err
	}

	// Mixed business logic with infrastructure concerns
	if os.Getenv("VAULT_TOKEN") == "" {
		fmt.Println("No vault token found") //  Direct output
		return errors.New("authentication required")
	}

	// Direct file system access
	data, err := ioutil.ReadFile("/etc/vault/secrets")
	if err != nil {
		fmt.Printf("Error reading secrets: %v\n", err) //  Mixed concerns
		return err
	}

	// Direct command execution
	cmd := exec.Command("vault", "auth", "-method=userpass")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	fmt.Printf("Vault output: %s\n", output) //  Presentation in business logic
	return nil
}
*/

// AFTER: Clean architecture with dependency injection
// This shows how the same functionality would be implemented

// IMPROVED: Clean separation of concerns
func NewVaultOperations(container *DIContainer) *VaultOperations {
	secretService, _ := container.GetSecretService()
	commandExec := container.GetCommandExecutor()
	return &VaultOperations{
		secretService: secretService,
		commandExec:   commandExec,
		logger:        zap.L(),
	}
}

type VaultOperations struct {
	secretService *SecretService
	commandExec   CommandExecutor
	logger        *zap.Logger
}

// Business logic is clean and testable
func (v *VaultOperations) AuthenticateUser(ctx context.Context, userID string) error {
	// Use domain service for business logic
	secret, err := v.secretService.GetSecret(ctx, userID, "vault_token")
	if err != nil {
		v.logger.Error("Authentication failed", zap.String("user", userID), zap.Error(err))
		return fmt.Errorf("vault authentication failed: %w", err)
	}

	if secret == nil || secret.Value == "" {
		v.logger.Warn("No vault token found", zap.String("user", userID))
		return fmt.Errorf("authentication required for user %s", userID)
	}

	v.logger.Info("User authenticated successfully", zap.String("user", userID))
	return nil
}

// Infrastructure concerns are abstracted away
func (v *VaultOperations) ExecuteVaultCommand(ctx context.Context, args []string) (*CommandResult, error) {
	cmd := &Command{
		Name: "vault",
		Args: args,
	}

	return v.commandExec.Execute(ctx, cmd)
}

// MIGRATION STRATEGY EXAMPLES

// Step 1: Extract interfaces from existing implementations
// Look at pkg/vault, identify what operations it performs, create interfaces

// Example: Current vault package has many responsibilities
// We can extract these interfaces:
// - SecretStore (for secret operations)
// - AuthenticationProvider (for auth operations)
// - ConfigurationManager (for vault config)

// Step 2: Create domain services that use these interfaces
// Move business logic from cmd/ packages into domain services

// Step 3: Implement interfaces using existing infrastructure code
// Wrap existing vault client, docker client, etc. to implement interfaces

// Step 4: Update command handlers to use dependency injection
// Replace direct dependencies with injected services

// CONCRETE MIGRATION EXAMPLE: pkg/vault refactoring

// Current vault package structure:
// pkg/vault/
//   ├── auth.go              (50+ dependencies)
//   ├── client.go            (direct API calls)
//   ├── config.go            (file system access)
//   └── operations.go        (mixed concerns)

// New structure:
// pkg/domain/vault/         (business logic, no external deps)
//   ├── service.go           (VaultService with interfaces)
//   └── entities.go          (domain entities)
// pkg/infrastructure/vault/ (implementation details)
//   ├── client.go            (implements SecretStore)
//   ├── auth_provider.go     (implements AuthenticationProvider)
//   └── config_repo.go       (implements ConfigRepository)

// Migration helper functions

// MigrateVaultPackage demonstrates how to refactor pkg/vault
func MigrateVaultPackage() {
	// Step 1: Identify current responsibilities
	responsibilities := []string{
		"Secret storage and retrieval",
		"User authentication",
		"Configuration management",
		"Audit logging",
		"Command execution",
		"File system operations",
	}

	// Step 2: Create domain interfaces for each responsibility
	// (Already done in interfaces.go)

	// Step 3: Create domain service that coordinates these interfaces
	// (Already done in services.go)

	// Step 4: Implement interfaces using existing vault code
	// This would wrap the existing vault client

	fmt.Printf("Vault package migration plan:\n")
	for i, resp := range responsibilities {
		fmt.Printf("%d. Extract %s into domain interface\n", i+1, resp)
	}
}

// TESTING STRATEGY

// Before: Hard to test due to direct dependencies
/*
func TestOldVaultOperations(t *testing.T) {
	//  Cannot test without actual Vault server
	//  Cannot test without file system
	//  Cannot test without network access
	//  Tests are slow and brittle
}
*/

// After: Easy to test with mocks
/*
func TestNewVaultOperations(t *testing.T) {
	//  Fast unit tests with mocks
	mockSecretService := &MockSecretService{}
	mockCommandExec := &MockCommandExecutor{}
	logger := zap.NewNop()

	vaultOps := &VaultOperations{
		secretService: mockSecretService,
		commandExec:   mockCommandExec,
		logger:        logger,
	}

	// Test business logic in isolation
	err := vaultOps.AuthenticateUser(context.Background(), "test-user")
	assert.NoError(t, err)
}
*/

// PERFORMANCE BENEFITS

// 1. Faster compilation: Reduced import cycles
// 2. Faster tests: Mock dependencies instead of real infrastructure
// 3. Better caching: Smaller, focused packages compile independently
// 4. Reduced memory usage: Only load what you need

// MAINTAINABILITY BENEFITS

// 1. Clear boundaries: Each layer has specific responsibilities
// 2. Easy to change: Swap implementations without changing business logic
// 3. Easy to extend: Add new providers/repositories without core changes
// 4. Easy to understand: Follows established patterns

// IMPLEMENTATION TIMELINE

// Week 1: Create architecture package with interfaces and examples
// Week 2: Migrate one high-impact package (e.g., pkg/vault)
// Week 3: Update related command handlers to use new architecture
// Week 4: Add comprehensive tests and documentation
// Week 5: Migrate remaining packages incrementally
// Week 6: Remove deprecated direct dependency patterns

// COMPATIBILITY STRATEGY

// Maintain backward compatibility during migration:
// 1. Keep existing public APIs
// 2. Add new clean architecture APIs alongside
// 3. Gradually migrate internal usage
// 4. Deprecate old APIs with clear migration path
// 5. Remove deprecated APIs in next major version

// Example compatibility wrapper
type CompatibilityWrapper struct {
	newService *SecretService
}

// Old API maintained for compatibility
func (c *CompatibilityWrapper) GetVaultSecret(key string) (string, error) {
	secret, err := c.newService.GetSecret(context.Background(), "system", key)
	if err != nil {
		return "", err
	}
	return secret.Value, nil
}

// GRADUAL MIGRATION CHECKLIST

//  Define domain interfaces
//  Create domain services
//  Implement dependency injection container
//  Create example implementations
//  Migrate one package (pkg/vault recommended)
//  Update command handlers
//  Add comprehensive tests
//  Document migration patterns
//  Migrate remaining packages
//  Remove deprecated patterns
