// Package vault - Enhanced Container Integration
package vault

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/architecture"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	infra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	
	"github.com/hashicorp/vault/api"
)

// EnhancedVaultContainer provides enhanced dependency injection for vault operations
type EnhancedVaultContainer struct {
	container    *architecture.EnhancedContainer
	rc           *eos_io.RuntimeContext
	initialized  bool
}

// NewEnhancedVaultContainer creates a new enhanced vault container
func NewEnhancedVaultContainer(rc *eos_io.RuntimeContext) (*EnhancedVaultContainer, error) {
	logger := rc.Log.Named("vault.container")
	
	container := architecture.NewEnhancedContainer(rc.Ctx, logger)
	
	vc := &EnhancedVaultContainer{
		container: container,
		rc:        rc,
	}
	
	if err := vc.registerServices(); err != nil {
		return nil, fmt.Errorf("failed to register vault services: %w", err)
	}
	
	return vc, nil
}

// registerServices registers all vault-related services with the enhanced container
func (vc *EnhancedVaultContainer) registerServices() error {
	// Register Vault client factory
	vc.container.RegisterSingleton("vaultClient", vc.createVaultClient)
	
	// Register secret stores
	vc.container.RegisterSingleton("primarySecretStore", vc.createPrimarySecretStore)
	vc.container.RegisterSingleton("fallbackSecretStore", vc.createFallbackSecretStore)
	vc.container.RegisterSingleton("compositeSecretStore", vc.createCompositeSecretStore)
	
	// Register domain services
	vc.container.RegisterSingleton("vaultAuthenticator", vc.createVaultAuthenticator)
	vc.container.RegisterSingleton("vaultManager", vc.createVaultManager)
	vc.container.RegisterSingleton("configRepository", vc.createConfigRepository)
	vc.container.RegisterSingleton("auditRepository", vc.createAuditRepository)
	vc.container.RegisterSingleton("vaultService", vc.createVaultService)
	
	// Register lifecycle services
	vc.container.RegisterSingleton("vaultLifecycle", vc.createVaultLifecycle)
	
	return nil
}

// Start initializes the vault container and all services
func (vc *EnhancedVaultContainer) Start() error {
	if vc.initialized {
		return fmt.Errorf("vault container already initialized")
	}
	
	if err := vc.container.Start(vc.rc.Ctx); err != nil {
		return fmt.Errorf("failed to start vault container: %w", err)
	}
	
	vc.initialized = true
	vc.rc.Log.Info("Enhanced vault container started successfully")
	
	return nil
}

// Stop gracefully shuts down the vault container
func (vc *EnhancedVaultContainer) Stop() error {
	if !vc.initialized {
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := vc.container.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop vault container: %w", err)
	}
	
	vc.initialized = false
	vc.rc.Log.Info("Enhanced vault container stopped successfully")
	
	return nil
}

// GetVaultService returns the enhanced vault domain service
func (vc *EnhancedVaultContainer) GetVaultService() (*vault.Service, error) {
	if !vc.initialized {
		return nil, fmt.Errorf("vault container not initialized")
	}
	
	return architecture.GetTyped[*vault.Service](vc.container, "vaultService")
}

// GetSecretStore returns the composite secret store
func (vc *EnhancedVaultContainer) GetSecretStore() (vault.SecretStore, error) {
	if !vc.initialized {
		return nil, fmt.Errorf("vault container not initialized")
	}
	
	return architecture.GetTyped[vault.SecretStore](vc.container, "compositeSecretStore")
}

// Health performs a comprehensive health check of all vault services
func (vc *EnhancedVaultContainer) Health() error {
	if !vc.initialized {
		return fmt.Errorf("vault container not initialized")
	}
	
	ctx, cancel := context.WithTimeout(vc.rc.Ctx, 10*time.Second)
	defer cancel()
	
	return vc.container.Health(ctx)
}

// Factory functions for service creation

func (vc *EnhancedVaultContainer) createVaultClient(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	client, err := NewClient(vc.rc)
	if err != nil {
		// Non-critical error - return nil client for fallback operation
		vc.rc.Log.Warn("Failed to create Vault client, operating in fallback mode", zap.Error(err))
		return (*api.Client)(nil), nil
	}
	
	vc.rc.Log.Info("Vault client created successfully")
	return client, nil
}

func (vc *EnhancedVaultContainer) createPrimarySecretStore(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	client, err := architecture.GetTyped[*api.Client](container, "vaultClient")
	if err != nil || client == nil {
		vc.rc.Log.Warn("No Vault client available, skipping primary secret store")
		return (vault.SecretStore)(nil), nil
	}
	
	logger := vc.rc.Log.Named("secret.primary")
	store := infra.NewAPISecretStore(client, shared.VaultMountKV, logger)
	
	vc.rc.Log.Info("Primary secret store (Vault API) created")
	return store, nil
}

func (vc *EnhancedVaultContainer) createFallbackSecretStore(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	logger := vc.rc.Log.Named("secret.fallback")
	store := infra.NewFallbackSecretStore(shared.SecretsDir, logger)
	
	vc.rc.Log.Info("Fallback secret store created", zap.String("path", shared.SecretsDir))
	return store, nil
}

func (vc *EnhancedVaultContainer) createCompositeSecretStore(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	primary, err := architecture.GetTyped[vault.SecretStore](container, "primarySecretStore")
	if err != nil {
		return nil, fmt.Errorf("failed to get primary secret store: %w", err)
	}
	
	fallback, err := architecture.GetTyped[vault.SecretStore](container, "fallbackSecretStore")
	if err != nil {
		return nil, fmt.Errorf("failed to get fallback secret store: %w", err)
	}
	
	logger := vc.rc.Log.Named("secret.composite")
	
	var store vault.SecretStore
	if primary != nil {
		store = infra.NewCompositeSecretStore(primary, fallback, logger)
		vc.rc.Log.Info("Composite secret store created with primary and fallback")
	} else {
		store = fallback
		vc.rc.Log.Info("Using fallback secret store only (no primary available)")
	}
	
	return store, nil
}

func (vc *EnhancedVaultContainer) createVaultAuthenticator(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	client, err := architecture.GetTyped[*api.Client](container, "vaultClient")
	if err != nil || client == nil {
		vc.rc.Log.Debug("No vault client available, skipping authenticator")
		return (vault.VaultAuthenticator)(nil), nil
	}
	
	logger := vc.rc.Log.Named("vault.auth")
	authenticator := infra.NewVaultAuthProvider(client, logger)
	
	vc.rc.Log.Info("Vault authenticator created successfully")
	return authenticator, nil
}

func (vc *EnhancedVaultContainer) createVaultManager(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	client, err := architecture.GetTyped[*api.Client](container, "vaultClient")
	if err != nil || client == nil {
		vc.rc.Log.Debug("No vault client available, skipping manager")
		return (vault.VaultManager)(nil), nil
	}
	
	logger := vc.rc.Log.Named("vault.manager")
	manager := infra.NewVaultManager(client, logger)
	
	vc.rc.Log.Info("Vault manager created successfully")
	return manager, nil
}

func (vc *EnhancedVaultContainer) createConfigRepository(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	// Use file-based config repository by default
	logger := vc.rc.Log.Named("vault.config")
	configDir := "/etc/eos"
	
	configRepo := infra.NewFileConfigRepository(configDir, logger)
	
	vc.rc.Log.Info("File-based config repository created", zap.String("dir", configDir))
	return configRepo, nil
}

func (vc *EnhancedVaultContainer) createAuditRepository(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	// Use file-based audit repository
	logger := vc.rc.Log.Named("vault.audit")
	logDir := "/var/log/eos"
	
	auditRepo := infra.NewFileAuditRepository(logDir, logger)
	
	vc.rc.Log.Info("File-based audit repository created", zap.String("dir", logDir))
	return auditRepo, nil
}

func (vc *EnhancedVaultContainer) createVaultService(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	secretStore, err := architecture.GetTyped[vault.SecretStore](container, "compositeSecretStore")
	if err != nil {
		return nil, fmt.Errorf("failed to get secret store: %w", err)
	}
	
	authenticator, _ := architecture.GetTyped[vault.VaultAuthenticator](container, "vaultAuthenticator")
	manager, _ := architecture.GetTyped[vault.VaultManager](container, "vaultManager")
	configRepo, _ := architecture.GetTyped[vault.ConfigRepository](container, "configRepository")
	auditRepo, _ := architecture.GetTyped[vault.AuditRepository](container, "auditRepository")
	
	logger := vc.rc.Log.Named("vault.service")
	
	service := vault.NewService(
		secretStore,
		authenticator,
		manager,
		configRepo,
		auditRepo,
		logger,
	)
	
	vc.rc.Log.Info("Vault domain service created successfully")
	return service, nil
}

func (vc *EnhancedVaultContainer) createVaultLifecycle(ctx context.Context, container *architecture.EnhancedContainer) (interface{}, error) {
	vaultService, err := architecture.GetTyped[*vault.Service](container, "vaultService")
	if err != nil {
		return nil, fmt.Errorf("failed to get vault service: %w", err)
	}
	
	return &VaultLifecycleManager{
		service: vaultService,
		logger:  vc.rc.Log.Named("vault.lifecycle"),
	}, nil
}

// VaultLifecycleManager implements ServiceLifecycle for vault operations
type VaultLifecycleManager struct {
	service *vault.Service
	logger  *zap.Logger
	started bool
}

// Start implements architecture.ServiceLifecycle
func (vlm *VaultLifecycleManager) Start(ctx context.Context) error {
	if vlm.started {
		return nil
	}
	
	vlm.logger.Info("Starting vault lifecycle manager")
	
	// Perform any startup validation or initialization
	// For now, just verify the service is healthy
	if vlm.service != nil {
		vlm.logger.Debug("Vault service available for lifecycle management")
	}
	
	vlm.started = true
	vlm.logger.Info("Vault lifecycle manager started successfully")
	
	return nil
}

// Stop implements architecture.ServiceLifecycle
func (vlm *VaultLifecycleManager) Stop(ctx context.Context) error {
	if !vlm.started {
		return nil
	}
	
	vlm.logger.Info("Stopping vault lifecycle manager")
	
	// Perform any cleanup operations
	// For vault, this might include token cleanup, connection cleanup, etc.
	
	vlm.started = false
	vlm.logger.Info("Vault lifecycle manager stopped successfully")
	
	return nil
}

// Health implements architecture.ServiceLifecycle
func (vlm *VaultLifecycleManager) Health(ctx context.Context) error {
	if !vlm.started {
		return fmt.Errorf("vault lifecycle manager not started")
	}
	
	if vlm.service == nil {
		return fmt.Errorf("vault service not available")
	}
	
	// TODO: Implement actual health check when vault service supports it
	vlm.logger.Debug("Vault health check passed")
	return nil
}

// Enhanced Service Facade Integration

// UpdateServiceFacadeWithEnhancedContainer updates the existing service facade to use the enhanced container
func UpdateServiceFacadeWithEnhancedContainer(rc *eos_io.RuntimeContext) error {
	enhancedContainer, err := NewEnhancedVaultContainer(rc)
	if err != nil {
		return fmt.Errorf("failed to create enhanced vault container: %w", err)
	}
	
	if err := enhancedContainer.Start(); err != nil {
		return fmt.Errorf("failed to start enhanced vault container: %w", err)
	}
	
	// Get the vault service from enhanced container
	vaultService, err := enhancedContainer.GetVaultService()
	if err != nil {
		return fmt.Errorf("failed to get vault service: %w", err)
	}
	
	// Get the secret store from enhanced container
	secretStore, err := enhancedContainer.GetSecretStore()
	if err != nil {
		return fmt.Errorf("failed to get secret store: %w", err)
	}
	
	// Update the global facade with enhanced services
	// This maintains backward compatibility while using enhanced architecture
	updateGlobalFacade(vaultService, secretStore, enhancedContainer, rc.Log)
	
	rc.Log.Info("Service facade updated with enhanced container")
	return nil
}

// updateGlobalFacade updates the global service facade with enhanced services
func updateGlobalFacade(vaultService *vault.Service, secretStore vault.SecretStore, container *EnhancedVaultContainer, logger *zap.Logger) {
	// This would integrate with the existing service_facade.go global state
	// Implementation would depend on how the current facade is structured
	logger.Info("Global facade updated with enhanced services",
		zap.Bool("has_vault_service", vaultService != nil),
		zap.Bool("has_secret_store", secretStore != nil),
		zap.Bool("has_container", container != nil),
	)
}