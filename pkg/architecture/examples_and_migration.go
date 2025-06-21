// Package architecture - Usage Examples and Migration Guide
package architecture

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ExampleUsage demonstrates how to use the enhanced container
func ExampleUsage() {
	// Create context and logger
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()
	
	// Build container with enhanced patterns
	container := NewContainerBuilder(ctx, logger).
		WithSingleton("secretStore", createSecretStore).
		WithSingleton("auditRepo", createAuditRepository).
		WithSingleton("infraProvider", createInfraProvider).
		WithSingleton("containerMgr", createContainerManager).
		WithSingleton("serviceMgr", createServiceManager).
		WithSingleton("infraService", createInfraService).
		MustBuild()

	// Start container (initializes all services with lifecycle)
	if err := container.Start(ctx); err != nil {
		logger.Fatal("Failed to start container", zap.Error(err))
	}
	defer func() {
		if err := container.Stop(ctx); err != nil {
			logger.Error("Failed to stop container", zap.Error(err))
		}
	}()

	// Use services with type safety
	infraService, err := GetTyped[*EnhancedInfrastructureService](container, "infraService")
	if err != nil {
		logger.Fatal("Failed to get infrastructure service", zap.Error(err))
	}

	// Use the service
	status, err := infraService.GetInfrastructureStatus(ctx, "user123")
	if err != nil {
		logger.Error("Failed to get status", zap.Error(err))
		return
	}

	logger.Info("Infrastructure status retrieved",
		zap.String("request_id", status.RequestID),
		zap.Int("servers", len(status.Servers)),
	)

	// Check container health
	if err := container.Health(ctx); err != nil {
		logger.Warn("Container health check failed", zap.Error(err))
	}

	// Get service information
	serviceInfo, _ := container.GetServiceInfo("infraService")
	logger.Info("Service info", zap.Any("info", serviceInfo))
}

// Factory functions for dependency injection

func createSecretStore(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	// In real implementation, this would create actual secret store
	return &MockSecretStore{}, nil
}

func createAuditRepository(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &MockAuditRepository{}, nil
}

func createInfraProvider(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &MockInfraProvider{}, nil
}

func createContainerManager(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &MockContainerManager{}, nil
}

func createServiceManager(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &MockServiceManager{}, nil
}

func createInfraService(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	// Resolve dependencies
	provider, err := GetTyped[InfrastructureProvider](container, "infraProvider")
	if err != nil {
		return nil, err
	}

	containerMgr, err := GetTyped[ContainerManager](container, "containerMgr")
	if err != nil {
		return nil, err
	}

	serviceMgr, err := GetTyped[ServiceManager](container, "serviceMgr")
	if err != nil {
		return nil, err
	}

	auditRepo, err := GetTyped[AuditRepository](container, "auditRepo")
	if err != nil {
		return nil, err
	}

	logger, _ := zap.NewDevelopment()

	return NewEnhancedInfrastructureService(
		provider,
		containerMgr,
		serviceMgr,
		auditRepo,
		logger,
	), nil
}

// Migration Examples

// BeforeMigration shows the old container usage pattern
func BeforeMigration() {
	logger, _ := zap.NewDevelopment()
	
	// Old pattern - manual dependency management
	container := NewDIContainer(logger)
	
	// Manual registration
	container.RegisterSecretStore(&MockSecretStore{})
	container.RegisterAuditRepository(&MockAuditRepository{})
	container.RegisterInfrastructureProvider(&MockInfraProvider{})
	container.RegisterContainerManager(&MockContainerManager{})
	container.RegisterServiceManager(&MockServiceManager{})

	// Get service (no lifecycle management)
	service, err := container.GetInfrastructureService()
	if err != nil {
		logger.Fatal("Failed to get service", zap.Error(err))
	}

	// Use service (no context, no timeout, no metrics)
	status, err := service.GetInfrastructureStatus(context.Background(), "user123")
	if err != nil {
		logger.Error("Failed to get status", zap.Error(err))
	}

	logger.Info("Status retrieved", zap.Int("servers", len(status.Servers)))
}

// AfterMigration shows the new enhanced container usage
func AfterMigration() {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()
	
	// New pattern - enhanced container with lifecycle
	container := NewContainerBuilder(ctx, logger).
		WithSingleton("secretStore", createSecretStore).
		WithSingleton("auditRepo", createAuditRepository).
		WithSingleton("infraProvider", createInfraProvider).
		WithSingleton("containerMgr", createContainerManager).
		WithSingleton("serviceMgr", createServiceManager).
		WithSingleton("infraService", createInfraService).
		MustBuild()

	// Start container (lifecycle management)
	if err := container.Start(ctx); err != nil {
		logger.Fatal("Failed to start container", zap.Error(err))
	}
	defer func() {
		if err := container.Stop(ctx); err != nil {
			logger.Error("Failed to stop container", zap.Error(err))
		}
	}()

	// Get service with type safety
	service, err := GetTyped[*EnhancedInfrastructureService](container, "infraService")
	if err != nil {
		logger.Fatal("Failed to get service", zap.Error(err))
	}

	// Use service with timeout and enhanced features
	status, err := service.GetInfrastructureStatus(ctx, "user123")
	if err != nil {
		logger.Error("Failed to get status", zap.Error(err))
		return
	}

	// Enhanced logging with metrics
	metrics := service.GetMetrics()
	logger.Info("Status retrieved with metrics",
		zap.String("request_id", status.RequestID),
		zap.Int("servers", len(status.Servers)),
		zap.Int64("total_requests", metrics.RequestCount),
		zap.Duration("avg_latency", metrics.AverageLatency),
	)

	// Health monitoring
	if err := container.Health(ctx); err != nil {
		logger.Warn("Health check failed", zap.Error(err))
	}
}

// CommandLayerMigration shows how to migrate command handlers
func CommandLayerMigration() {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// Create application container
	appContainer := NewContainerBuilder(ctx, logger).
		WithSingleton("secretStore", createSecretStore).
		WithSingleton("auditRepo", createAuditRepository).
		WithSingleton("infraProvider", createInfraProvider).
		WithSingleton("containerMgr", createContainerManager).
		WithSingleton("serviceMgr", createServiceManager).
		WithSingleton("infraService", createInfraService).
		MustBuild()

	// Start application
	if err := appContainer.Start(ctx); err != nil {
		logger.Fatal("Failed to start application", zap.Error(err))
	}
	defer func() {
		if err := appContainer.Stop(ctx); err != nil {
			logger.Error("Failed to stop application", zap.Error(err))
		}
	}()

	// Example command handler
	createServerCommand := func(serverName, serverType string) error {
		service, err := GetTyped[*EnhancedInfrastructureService](appContainer, "infraService")
		if err != nil {
			return fmt.Errorf("failed to get infrastructure service: %w", err)
		}

		spec := &ServerSpec{
			Name:  serverName,
			Type:  serverType,
			Image: "ubuntu-20.04",
		}

		server, err := service.CreateServerWithTimeout(ctx, "cli-user", spec, 5*time.Minute)
		if err != nil {
			return fmt.Errorf("failed to create server: %w", err)
		}

		logger.Info("Server created successfully",
			zap.String("server_id", server.ID),
			zap.String("server_name", server.Name),
		)

		return nil
	}

	// Use the command
	if err := createServerCommand("test-server", "cx11"); err != nil {
		logger.Error("Command failed", zap.Error(err))
	}
}

// Mock implementations for examples

type MockSecretStore struct{}

func (m *MockSecretStore) Get(ctx context.Context, key string) (*Secret, error) {
	return &Secret{Key: key, Value: "mock-value"}, nil
}

func (m *MockSecretStore) Set(ctx context.Context, key string, secret *Secret) error {
	return nil
}

func (m *MockSecretStore) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *MockSecretStore) List(ctx context.Context, prefix string) ([]*Secret, error) {
	return []*Secret{{Key: prefix + "1", Value: "value1"}}, nil
}

type MockAuditRepository struct{}

func (m *MockAuditRepository) Record(ctx context.Context, event *AuditEvent) error {
	return nil
}

func (m *MockAuditRepository) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	return []*AuditEvent{}, nil
}

type MockInfraProvider struct{}

func (m *MockInfraProvider) GetServers(ctx context.Context) ([]*Server, error) {
	return []*Server{{ID: "1", Name: "test-server", Status: "running"}}, nil
}

func (m *MockInfraProvider) CreateServer(ctx context.Context, spec *ServerSpec) (*Server, error) {
	return &Server{
		ID:       "new-server-1",
		Name:     spec.Name,
		Provider: "mock",
		Status:   "running",
		Created:  time.Now(),
	}, nil
}

func (m *MockInfraProvider) DeleteServer(ctx context.Context, serverID string) error {
	return nil
}

func (m *MockInfraProvider) GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	return &NetworkInfo{
		Interfaces: []NetworkInterface{
			{Name: "eth0", Status: "up"},
		},
	}, nil
}

type MockContainerManager struct{}

func (m *MockContainerManager) ListContainers(ctx context.Context) ([]*Container, error) {
	return []*Container{{
		ID:      "1",
		Name:    "test-container", 
		Image:   "nginx",
		Status:  "running",
		Created: time.Now(),
	}}, nil
}

func (m *MockContainerManager) GetContainer(ctx context.Context, id string) (*Container, error) {
	return &Container{
		ID:      id,
		Name:    "test-container",
		Image:   "nginx", 
		Status:  "running",
		Created: time.Now(),
	}, nil
}

func (m *MockContainerManager) CreateContainer(ctx context.Context, spec *ContainerSpec) (*Container, error) {
	return &Container{
		ID:      "new-1",
		Name:    spec.Name,
		Image:   spec.Image,
		Status:  "running", 
		Created: time.Now(),
	}, nil
}

func (m *MockContainerManager) StopContainer(ctx context.Context, id string) error {
	return nil
}

type MockServiceManager struct{}

func (m *MockServiceManager) ListServices(ctx context.Context) ([]*Service, error) {
	return []*Service{{Name: "test-service", Status: "active", Enabled: true}}, nil
}

func (m *MockServiceManager) GetService(ctx context.Context, name string) (*Service, error) {
	return &Service{Name: name, Status: "active", Enabled: true}, nil
}

func (m *MockServiceManager) StartService(ctx context.Context, name string) error {
	return nil
}

func (m *MockServiceManager) StopService(ctx context.Context, name string) error {
	return nil
}

func (m *MockServiceManager) EnableService(ctx context.Context, name string) error {
	return nil
}