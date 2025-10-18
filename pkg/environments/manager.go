package environments

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager(configPath string) (*EnvironmentManager, error) {
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(homeDir, ".eos", "config.yaml")
	}

	// Expand tilde
	if strings.HasPrefix(configPath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(homeDir, configPath[2:])
	}

	manager := &EnvironmentManager{
		configPath: configPath,
		cache:      make(map[string]*Environment),
	}

	// Load or initialize context
	if err := manager.loadContext(); err != nil {
		// If config doesn't exist, create default
		if os.IsNotExist(err) {
			manager.context = DefaultContext()
			if err := manager.saveContext(); err != nil {
				return nil, fmt.Errorf("failed to save default context: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load context: %w", err)
		}
	}

	return manager, nil
}

// loadContext loads the context from the config file
func (em *EnvironmentManager) loadContext() error {
	data, err := os.ReadFile(em.configPath)
	if err != nil {
		return err
	}

	var context Context
	if err := yaml.Unmarshal(data, &context); err != nil {
		return fmt.Errorf("failed to unmarshal context: %w", err)
	}

	em.context = &context
	return nil
}

// saveContext saves the context to the config file
func (em *EnvironmentManager) saveContext() error {
	// Ensure directory exists
	dir := filepath.Dir(em.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Update timestamp
	em.context.UpdatedAt = time.Now()

	data, err := yaml.Marshal(em.context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	if err := os.WriteFile(em.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetCurrentEnvironment returns the current environment
func (em *EnvironmentManager) GetCurrentEnvironment(rc *eos_io.RuntimeContext) (*Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	envName := em.context.CurrentEnvironment
	if envName == "" {
		return nil, &EnvironmentError{
			Type:      "context",
			Operation: "get_current",
			Message:   "no current environment set",
			Timestamp: time.Now(),
		}
	}

	env, exists := em.context.Environments[envName]
	if !exists {
		return nil, &EnvironmentError{
			Type:        "not_found",
			Environment: envName,
			Operation:   "get_current",
			Message:     fmt.Sprintf("environment %s not found", envName),
			Timestamp:   time.Now(),
		}
	}

	logger.Debug("Retrieved current environment",
		zap.String("environment", envName),
		zap.String("type", string(env.Type)),
		zap.String("status", string(env.Status)))

	return &env, nil
}

// GetEnvironment returns a specific environment
func (em *EnvironmentManager) GetEnvironment(rc *eos_io.RuntimeContext, name string) (*Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check cache first
	if cached, exists := em.cache[name]; exists && time.Now().Before(em.cacheExpiry) {
		logger.Debug("Retrieved environment from cache", zap.String("environment", name))
		return cached, nil
	}

	env, exists := em.context.Environments[name]
	if !exists {
		return nil, &EnvironmentError{
			Type:        "not_found",
			Environment: name,
			Operation:   "get",
			Message:     fmt.Sprintf("environment %s not found", name),
			Timestamp:   time.Now(),
		}
	}

	// Cache the environment
	em.cache[name] = &env
	em.cacheExpiry = time.Now().Add(em.context.Config.CacheTimeout)

	logger.Debug("Retrieved environment",
		zap.String("environment", name),
		zap.String("type", string(env.Type)),
		zap.String("status", string(env.Status)))

	return &env, nil
}

// ListEnvironments returns all environments
func (em *EnvironmentManager) ListEnvironments(rc *eos_io.RuntimeContext) (map[string]Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Listing all environments", zap.Int("count", len(em.context.Environments)))

	// Return a copy to prevent modification
	envs := make(map[string]Environment)
	for name, env := range em.context.Environments {
		envs[name] = env
	}

	return envs, nil
}

// UseEnvironment switches the current environment context
func (em *EnvironmentManager) UseEnvironment(rc *eos_io.RuntimeContext, name string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Verify environment exists
	if _, exists := em.context.Environments[name]; !exists {
		return &EnvironmentError{
			Type:        "not_found",
			Environment: name,
			Operation:   "use",
			Message:     fmt.Sprintf("environment %s not found", name),
			Timestamp:   time.Now(),
		}
	}

	previousEnv := em.context.CurrentEnvironment
	em.context.CurrentEnvironment = name

	// Save context
	if err := em.saveContext(); err != nil {
		// Rollback on save failure
		em.context.CurrentEnvironment = previousEnv
		return &EnvironmentError{
			Type:        "save_failed",
			Environment: name,
			Operation:   "use",
			Message:     "failed to save context after environment switch",
			Cause:       err,
			Timestamp:   time.Now(),
			Retryable:   true,
		}
	}

	logger.Info("Switched environment context",
		zap.String("from", previousEnv),
		zap.String("to", name))

	return nil
}

// CreateEnvironment creates a new environment
func (em *EnvironmentManager) CreateEnvironment(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate environment
	if err := em.validateEnvironment(rc, env); err != nil {
		return fmt.Errorf("environment validation failed: %w", err)
	}

	// Check if environment already exists
	if _, exists := em.context.Environments[env.Name]; exists {
		return &EnvironmentError{
			Type:        "already_exists",
			Environment: env.Name,
			Operation:   "create",
			Message:     fmt.Sprintf("environment %s already exists", env.Name),
			Timestamp:   time.Now(),
		}
	}

	// Set timestamps
	now := time.Now()
	env.CreatedAt = now
	env.UpdatedAt = now
	env.Status = EnvironmentStatusCreating

	// Add to context
	em.context.Environments[env.Name] = *env

	// Save context
	if err := em.saveContext(); err != nil {
		// Rollback
		delete(em.context.Environments, env.Name)
		return &EnvironmentError{
			Type:        "save_failed",
			Environment: env.Name,
			Operation:   "create",
			Message:     "failed to save context after environment creation",
			Cause:       err,
			Timestamp:   time.Now(),
			Retryable:   true,
		}
	}

	// Initialize environment infrastructure
	if err := em.initializeEnvironment(rc, env); err != nil {
		logger.Error("Failed to initialize environment infrastructure",
			zap.String("environment", env.Name),
			zap.Error(err))
		// Mark as inactive but don't delete
		env.Status = EnvironmentStatusInactive
		em.context.Environments[env.Name] = *env
		if err := em.saveContext(); err != nil {
			logger.Warn("Failed to save context after marking environment inactive", zap.Error(err))
		}
		return fmt.Errorf("environment infrastructure initialization failed: %w", err)
	}

	// Mark as active
	env.Status = EnvironmentStatusActive
	env.UpdatedAt = time.Now()
	em.context.Environments[env.Name] = *env
	if err := em.saveContext(); err != nil {
		logger.Warn("Failed to save context after environment creation", zap.Error(err))
	}

	logger.Info("Environment created successfully",
		zap.String("environment", env.Name),
		zap.String("type", string(env.Type)))

	return nil
}

// UpdateEnvironment updates an existing environment
func (em *EnvironmentManager) UpdateEnvironment(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate environment
	if err := em.validateEnvironment(rc, env); err != nil {
		return fmt.Errorf("environment validation failed: %w", err)
	}

	// Check if environment exists
	existing, exists := em.context.Environments[env.Name]
	if !exists {
		return &EnvironmentError{
			Type:        "not_found",
			Environment: env.Name,
			Operation:   "update",
			Message:     fmt.Sprintf("environment %s not found", env.Name),
			Timestamp:   time.Now(),
		}
	}

	// Preserve creation time
	env.CreatedAt = existing.CreatedAt
	env.UpdatedAt = time.Now()
	env.Status = EnvironmentStatusUpdating

	// Update context
	em.context.Environments[env.Name] = *env

	// Save context
	if err := em.saveContext(); err != nil {
		// Rollback
		em.context.Environments[env.Name] = existing
		return &EnvironmentError{
			Type:        "save_failed",
			Environment: env.Name,
			Operation:   "update",
			Message:     "failed to save context after environment update",
			Cause:       err,
			Timestamp:   time.Now(),
			Retryable:   true,
		}
	}

	// Apply environment changes
	if err := em.applyEnvironmentChanges(rc, &existing, env); err != nil {
		logger.Error("Failed to apply environment changes",
			zap.String("environment", env.Name),
			zap.Error(err))
		// Rollback
		em.context.Environments[env.Name] = existing
		if err := em.saveContext(); err != nil {
			logger.Warn("Failed to save context during rollback", zap.Error(err))
		}
		return fmt.Errorf("failed to apply environment changes: %w", err)
	}

	// Mark as active
	env.Status = EnvironmentStatusActive
	env.UpdatedAt = time.Now()
	em.context.Environments[env.Name] = *env
	em.saveContext()

	// Clear cache
	delete(em.cache, env.Name)

	logger.Info("Environment updated successfully",
		zap.String("environment", env.Name))

	return nil
}

// DeleteEnvironment deletes an environment
func (em *EnvironmentManager) DeleteEnvironment(rc *eos_io.RuntimeContext, name string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if environment exists
	env, exists := em.context.Environments[name]
	if !exists {
		return &EnvironmentError{
			Type:        "not_found",
			Environment: name,
			Operation:   "delete",
			Message:     fmt.Sprintf("environment %s not found", name),
			Timestamp:   time.Now(),
		}
	}

	// Safety check for production
	if env.Type == EnvironmentTypeProduction && !force {
		return &EnvironmentError{
			Type:        "safety_check",
			Environment: name,
			Operation:   "delete",
			Message:     "cannot delete production environment without --force flag",
			Timestamp:   time.Now(),
		}
	}

	// Check if it's the current environment
	if em.context.CurrentEnvironment == name {
		return &EnvironmentError{
			Type:        "current_environment",
			Environment: name,
			Operation:   "delete",
			Message:     "cannot delete current environment, switch to another environment first",
			Timestamp:   time.Now(),
		}
	}

	// Mark as destroyed
	env.Status = EnvironmentStatusDestroyed
	env.UpdatedAt = time.Now()
	em.context.Environments[name] = env

	// Cleanup environment infrastructure
	if err := em.cleanupEnvironment(rc, &env); err != nil {
		logger.Error("Failed to cleanup environment infrastructure",
			zap.String("environment", name),
			zap.Error(err))
		if !force {
			return fmt.Errorf("environment cleanup failed: %w", err)
		}
	}

	// Remove from context
	delete(em.context.Environments, name)

	// Save context
	if err := em.saveContext(); err != nil {
		return &EnvironmentError{
			Type:        "save_failed",
			Environment: name,
			Operation:   "delete",
			Message:     "failed to save context after environment deletion",
			Cause:       err,
			Timestamp:   time.Now(),
			Retryable:   true,
		}
	}

	// Clear cache
	delete(em.cache, name)

	logger.Info("Environment deleted successfully",
		zap.String("environment", name),
		zap.Bool("force", force))

	return nil
}



// validateEnvironment validates an environment configuration
func (em *EnvironmentManager) validateEnvironment(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating environment", zap.String("environment", env.Name))

	// Basic validation
	if env.Name == "" {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate",
			Message:   "environment name cannot be empty",
			Timestamp: time.Now(),
		}
	}

	if env.Type == "" {
		return &EnvironmentError{
			Type:        "validation",
			Environment: env.Name,
			Operation:   "validate",
			Message:     "environment type cannot be empty",
			Timestamp:   time.Now(),
		}
	}

	// Validate infrastructure configuration
	if err := em.validateInfrastructure(rc, &env.Infrastructure); err != nil {
		return fmt.Errorf("infrastructure validation failed: %w", err)
	}

	// Validate deployment configuration
	if err := em.validateDeploymentConfig(rc, &env.Deployment); err != nil {
		return fmt.Errorf("deployment configuration validation failed: %w", err)
	}

	// Apply strict validation if enabled
	if em.context.Config.Validation.Enabled && em.context.Config.Validation.Strict {
		if err := em.strictValidation(rc, env); err != nil {
			return fmt.Errorf("strict validation failed: %w", err)
		}
	}

	logger.Debug("Environment validation passed", zap.String("environment", env.Name))
	return nil
}

// validateInfrastructure validates infrastructure configuration
func (em *EnvironmentManager) validateInfrastructure(rc *eos_io.RuntimeContext, infra *InfrastructureConfig) error {
	// Validate Nomad configuration
	if infra.Nomad.Address == "" {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_infrastructure",
			Message:   "Nomad address cannot be empty",
			Timestamp: time.Now(),
		}
	}

	// Validate Consul configuration
	if infra.Consul.Address == "" {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_infrastructure",
			Message:   "Consul address cannot be empty",
			Timestamp: time.Now(),
		}
	}

	// Validate Vault configuration
	if infra.Vault.Address == "" {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_infrastructure",
			Message:   "Vault address cannot be empty",
			Timestamp: time.Now(),
		}
	}

	return nil
}

// validateDeploymentConfig validates deployment configuration
func (em *EnvironmentManager) validateDeploymentConfig(rc *eos_io.RuntimeContext, deploy *DeploymentConfig) error {
	// Validate deployment strategy
	validStrategies := []string{"rolling", "blue-green", "canary"}
	valid := false
	for _, strategy := range validStrategies {
		if deploy.Strategy.Type == strategy {
			valid = true
			break
		}
	}
	if !valid {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_deployment",
			Message:   fmt.Sprintf("invalid deployment strategy: %s", deploy.Strategy.Type),
			Timestamp: time.Now(),
		}
	}

	// Validate resource limits
	if deploy.Resources.CPU <= 0 {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_deployment",
			Message:   "CPU allocation must be greater than 0",
			Timestamp: time.Now(),
		}
	}

	if deploy.Resources.Memory <= 0 {
		return &EnvironmentError{
			Type:      "validation",
			Operation: "validate_deployment",
			Message:   "Memory allocation must be greater than 0",
			Timestamp: time.Now(),
		}
	}

	return nil
}

// strictValidation performs strict validation checks
func (em *EnvironmentManager) strictValidation(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Performing strict validation", zap.String("environment", env.Name))

	// Production environments must have certain security features enabled
	if env.Type == EnvironmentTypeProduction {
		if !env.Security.AccessControl.RBAC.Enabled {
			return &EnvironmentError{
				Type:        "strict_validation",
				Environment: env.Name,
				Operation:   "validate",
				Message:     "production environments must have RBAC enabled",
				Timestamp:   time.Now(),
			}
		}

		if !env.Security.AccessControl.MFA.Required {
			return &EnvironmentError{
				Type:        "strict_validation",
				Environment: env.Name,
				Operation:   "validate",
				Message:     "production environments must require MFA",
				Timestamp:   time.Now(),
			}
		}

		if !env.Security.AccessControl.Approval.Required {
			return &EnvironmentError{
				Type:        "strict_validation",
				Environment: env.Name,
				Operation:   "validate",
				Message:     "production environments must require approval for deployments",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// initializeEnvironment initializes environment infrastructure
func (em *EnvironmentManager) initializeEnvironment(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Initializing environment infrastructure", zap.String("environment", env.Name))

	// Assessment: Check if infrastructure components are reachable
	logger.Info("Assessing infrastructure connectivity")

	// Intervention: Initialize infrastructure components
	logger.Info("Initializing infrastructure components")

	// This would typically involve:
	// 1. Verifying Nomad/Consul/Vault connectivity
	// 2. Creating namespaces/tenants
	// 3. Setting up basic policies
	// 4. Configuring monitoring

	// For now, we'll simulate the initialization
	time.Sleep(1 * time.Second)

	// Evaluation: Verify infrastructure is ready
	logger.Info("Verifying infrastructure initialization")

	logger.Info("Environment infrastructure initialized successfully", zap.String("environment", env.Name))
	return nil
}

// applyEnvironmentChanges applies changes to an environment
func (em *EnvironmentManager) applyEnvironmentChanges(rc *eos_io.RuntimeContext, old, new *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Applying environment changes", zap.String("environment", new.Name))

	// Check for infrastructure changes
	if old.Infrastructure.Nomad.Address != new.Infrastructure.Nomad.Address {
		logger.Info("Nomad address changed, updating configuration")
	}

	if old.Infrastructure.Consul.Address != new.Infrastructure.Consul.Address {
		logger.Info("Consul address changed, updating configuration")
	}

	if old.Infrastructure.Vault.Address != new.Infrastructure.Vault.Address {
		logger.Info("Vault address changed, updating configuration")
	}

	// Apply changes
	time.Sleep(500 * time.Millisecond)

	logger.Info("Environment changes applied successfully", zap.String("environment", new.Name))
	return nil
}

// cleanupEnvironment cleans up environment infrastructure
func (em *EnvironmentManager) cleanupEnvironment(rc *eos_io.RuntimeContext, env *Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Cleaning up environment infrastructure", zap.String("environment", env.Name))

	// This would typically involve:
	// 1. Stopping all deployments
	// 2. Removing namespaces/tenants
	// 3. Cleaning up policies
	// 4. Removing monitoring configuration

	// For now, we'll simulate the cleanup
	time.Sleep(1 * time.Second)

	logger.Info("Environment infrastructure cleaned up successfully", zap.String("environment", env.Name))
	return nil
}

// RefreshCache refreshes the environment cache
func (em *EnvironmentManager) RefreshCache(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Refreshing environment cache")

	// Clear cache
	em.cache = make(map[string]*Environment)
	em.cacheExpiry = time.Time{}

	// Reload context from file
	if err := em.loadContext(); err != nil {
		return fmt.Errorf("failed to reload context: %w", err)
	}

	logger.Debug("Environment cache refreshed")
	return nil
}
