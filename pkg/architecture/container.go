// Package architecture - Dependency Injection Container
package architecture

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// DIContainer manages dependencies and provides dependency injection
type DIContainer struct {
	// Infrastructure dependencies
	infraProvider   InfrastructureProvider
	containerMgr    ContainerManager
	serviceMgr      ServiceManager
	commandExecutor CommandExecutor

	// Storage dependencies
	secretStore SecretStore
	configRepo  ConfigRepository
	auditRepo   AuditRepository

	// Services (business logic)
	infraService  *InfrastructureService
	secretService *SecretService

	// Cross-cutting concerns
	logger *zap.Logger
}

// NewDIContainer creates a new dependency injection container
func NewDIContainer(logger *zap.Logger) *DIContainer {
	return &DIContainer{
		logger: logger,
	}
}

// RegisterInfrastructureProvider registers an infrastructure provider
func (c *DIContainer) RegisterInfrastructureProvider(provider InfrastructureProvider) {
	c.infraProvider = provider
}

// RegisterContainerManager registers a container manager
func (c *DIContainer) RegisterContainerManager(mgr ContainerManager) {
	c.containerMgr = mgr
}

// RegisterServiceManager registers a service manager
func (c *DIContainer) RegisterServiceManager(mgr ServiceManager) {
	c.serviceMgr = mgr
}

// RegisterCommandExecutor registers a command executor
func (c *DIContainer) RegisterCommandExecutor(executor CommandExecutor) {
	c.commandExecutor = executor
}

// RegisterSecretStore registers a secret store
func (c *DIContainer) RegisterSecretStore(store SecretStore) {
	c.secretStore = store
}

// RegisterConfigRepository registers a config repository
func (c *DIContainer) RegisterConfigRepository(repo ConfigRepository) {
	c.configRepo = repo
}

// RegisterAuditRepository registers an audit repository
func (c *DIContainer) RegisterAuditRepository(repo AuditRepository) {
	c.auditRepo = repo
}

// GetInfrastructureService returns the infrastructure service, creating it if necessary
func (c *DIContainer) GetInfrastructureService() (*InfrastructureService, error) {
	if c.infraService == nil {
		if err := c.validateInfrastructureDependencies(); err != nil {
			return nil, fmt.Errorf("missing infrastructure dependencies: %w", err)
		}

		c.infraService = NewInfrastructureService(
			c.infraProvider,
			c.containerMgr,
			c.serviceMgr,
			c.auditRepo,
			c.logger,
		)
	}
	return c.infraService, nil
}

// GetSecretService returns the secret service, creating it if necessary
func (c *DIContainer) GetSecretService() (*SecretService, error) {
	if c.secretService == nil {
		if err := c.validateSecretDependencies(); err != nil {
			return nil, fmt.Errorf("missing secret dependencies: %w", err)
		}

		c.secretService = NewSecretService(
			c.secretStore,
			c.auditRepo,
			c.logger,
		)
	}
	return c.secretService, nil
}

// GetSecretStore returns the registered secret store
func (c *DIContainer) GetSecretStore() SecretStore {
	return c.secretStore
}

// GetConfigRepository returns the registered config repository
func (c *DIContainer) GetConfigRepository() ConfigRepository {
	return c.configRepo
}

// GetAuditRepository returns the registered audit repository
func (c *DIContainer) GetAuditRepository() AuditRepository {
	return c.auditRepo
}

// GetCommandExecutor returns the registered command executor
func (c *DIContainer) GetCommandExecutor() CommandExecutor {
	return c.commandExecutor
}

// ValidateAll validates that all required dependencies are registered
func (c *DIContainer) ValidateAll() error {
	if err := c.validateInfrastructureDependencies(); err != nil {
		return err
	}
	if err := c.validateSecretDependencies(); err != nil {
		return err
	}
	return nil
}

// validateInfrastructureDependencies checks infrastructure service dependencies
func (c *DIContainer) validateInfrastructureDependencies() error {
	if c.infraProvider == nil {
		return fmt.Errorf("infrastructure provider not registered")
	}
	if c.containerMgr == nil {
		return fmt.Errorf("container manager not registered")
	}
	if c.serviceMgr == nil {
		return fmt.Errorf("service manager not registered")
	}
	if c.auditRepo == nil {
		return fmt.Errorf("audit repository not registered")
	}
	return nil
}

// validateSecretDependencies checks secret service dependencies
func (c *DIContainer) validateSecretDependencies() error {
	if c.secretStore == nil {
		return fmt.Errorf("secret store not registered")
	}
	if c.auditRepo == nil {
		return fmt.Errorf("audit repository not registered")
	}
	return nil
}

// ApplicationContext provides application-wide dependencies
type ApplicationContext struct {
	Container *DIContainer
	Logger    *zap.Logger
	Context   context.Context
}

// NewApplicationContext creates a new application context
func NewApplicationContext(ctx context.Context, logger *zap.Logger) *ApplicationContext {
	return &ApplicationContext{
		Container: NewDIContainer(logger),
		Logger:    logger,
		Context:   ctx,
	}
}

// ConfigurationBuilder helps build container configuration
type ConfigurationBuilder struct {
	container *DIContainer
	logger    *zap.Logger
}

// NewConfigurationBuilder creates a new configuration builder
func NewConfigurationBuilder(logger *zap.Logger) *ConfigurationBuilder {
	return &ConfigurationBuilder{
		container: NewDIContainer(logger),
		logger:    logger,
	}
}

// WithInfrastructureProvider adds infrastructure provider
func (b *ConfigurationBuilder) WithInfrastructureProvider(provider InfrastructureProvider) *ConfigurationBuilder {
	b.container.RegisterInfrastructureProvider(provider)
	return b
}

// WithContainerManager adds container manager
func (b *ConfigurationBuilder) WithContainerManager(mgr ContainerManager) *ConfigurationBuilder {
	b.container.RegisterContainerManager(mgr)
	return b
}

// WithServiceManager adds service manager
func (b *ConfigurationBuilder) WithServiceManager(mgr ServiceManager) *ConfigurationBuilder {
	b.container.RegisterServiceManager(mgr)
	return b
}

// WithSecretStore adds secret store
func (b *ConfigurationBuilder) WithSecretStore(store SecretStore) *ConfigurationBuilder {
	b.container.RegisterSecretStore(store)
	return b
}

// WithConfigRepository adds config repository
func (b *ConfigurationBuilder) WithConfigRepository(repo ConfigRepository) *ConfigurationBuilder {
	b.container.RegisterConfigRepository(repo)
	return b
}

// WithAuditRepository adds audit repository
func (b *ConfigurationBuilder) WithAuditRepository(repo AuditRepository) *ConfigurationBuilder {
	b.container.RegisterAuditRepository(repo)
	return b
}

// WithCommandExecutor adds command executor
func (b *ConfigurationBuilder) WithCommandExecutor(executor CommandExecutor) *ConfigurationBuilder {
	b.container.RegisterCommandExecutor(executor)
	return b
}

// Build creates the final container with validation
func (b *ConfigurationBuilder) Build() (*DIContainer, error) {
	if err := b.container.ValidateAll(); err != nil {
		return nil, fmt.Errorf("container validation failed: %w", err)
	}
	return b.container, nil
}

// MustBuild creates the container or panics if validation fails
func (b *ConfigurationBuilder) MustBuild() *DIContainer {
	container, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("container build failed: %v", err))
	}
	return container
}
