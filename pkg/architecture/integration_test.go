// Package architecture - Integration Tests for Enhanced Container
package architecture

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestEnhancedContainerBasicFunctionality tests the core container operations
func TestEnhancedContainerBasicFunctionality(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// Test container creation
	container := NewEnhancedContainer(ctx, logger)
	require.NotNil(t, container)

	// Test service registration
	container.RegisterSingleton("testService", createTestService)

	// Test container validation
	err := container.Validate()
	assert.NoError(t, err)

	// Test container startup
	err = container.Start(ctx)
	assert.NoError(t, err)

	// Test service retrieval
	service, err := container.Get("testService")
	assert.NoError(t, err)
	assert.NotNil(t, service)

	// Test type-safe retrieval
	typedService, err := GetTyped[*TestService](container, "testService")
	assert.NoError(t, err)
	assert.NotNil(t, typedService)

	// Test health check
	err = container.Health(ctx)
	assert.NoError(t, err)

	// Test container shutdown
	err = container.Stop(ctx)
	assert.NoError(t, err)
}

// TestContainerBuilder tests the builder pattern
func TestContainerBuilder(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// Test builder pattern
	container, err := NewContainerBuilder(ctx, logger).
		WithSingleton("service1", createTestService).
		WithSingleton("service2", createAnotherTestService).
		WithTransient("transientService", createTransientService).
		Build()

	require.NoError(t, err)
	require.NotNil(t, container)

	// Start container
	err = container.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := container.Stop(ctx); err != nil {
			t.Errorf("Failed to stop container: %v", err)
		}
	}()

	// Test all services are available
	service1, err := container.Get("service1")
	assert.NoError(t, err)
	assert.NotNil(t, service1)

	service2, err := container.Get("service2")
	assert.NoError(t, err)
	assert.NotNil(t, service2)

	// Test transient service creates new instances
	transient1, err := container.Get("transientService")
	assert.NoError(t, err)
	assert.NotNil(t, transient1)

	transient2, err := container.Get("transientService")
	assert.NoError(t, err)
	assert.NotNil(t, transient2)

	// Transient services should be different instances
	assert.NotSame(t, transient1, transient2)
}

// TestServiceLifecycle tests service lifecycle management
func TestServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// Create container with lifecycle service
	lifecycleService := &TestLifecycleService{}

	container := NewEnhancedContainer(ctx, logger)
	err := container.RegisterInstance("lifecycleService", lifecycleService)
	require.NoError(t, err)

	// Start container - should call Start on lifecycle service
	err = container.Start(ctx)
	require.NoError(t, err)
	assert.True(t, lifecycleService.started)

	// Health check - should call Health on lifecycle service
	err = container.Health(ctx)
	assert.NoError(t, err)

	// Stop container - should call Stop on lifecycle service
	err = container.Stop(ctx)
	assert.NoError(t, err)
	assert.False(t, lifecycleService.started)
}

// TestContainerErrorHandling tests error scenarios
func TestContainerErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	container := NewEnhancedContainer(ctx, logger)

	// Test getting non-existent service
	_, err := container.Get("nonExistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")

	// Test registering nil instance
	err = container.RegisterInstance("nilService", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot register nil")

	// Test validation with missing dependencies
	container.RegisterSingleton("dependentService", createDependentService)
	err = container.Validate()
	assert.Error(t, err) // Should fail because dependency is missing
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	container := NewEnhancedContainer(ctx, logger)
	container.RegisterSingleton("testService", createTestService)

	err := container.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := container.Stop(ctx); err != nil {
			t.Errorf("Failed to stop container: %v", err)
		}
	}()

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Multiple goroutines accessing the same singleton
			service, err := container.Get("testService")
			assert.NoError(t, err)
			assert.NotNil(t, service)

			// Test health check concurrency
			err = container.Health(ctx)
			assert.NoError(t, err)
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestContainerMetrics tests service metrics collection
func TestContainerMetrics(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	container := NewEnhancedContainer(ctx, logger)
	container.RegisterSingleton("testService", createTestService)

	err := container.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := container.Stop(ctx); err != nil {
			t.Errorf("Failed to stop container: %v", err)
		}
	}()

	// Test service info collection
	info, err := container.GetServiceInfo("testService")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "testService", info.Name)
	assert.True(t, info.Singleton)

	// Test service names collection
	names := container.GetServiceNames()
	assert.Contains(t, names, "testService")
}

// Mock services for testing

type TestService struct {
	Name string
}

func createTestService(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &TestService{Name: "test"}, nil
}

type AnotherTestService struct {
	Value int
}

func createAnotherTestService(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &AnotherTestService{Value: 42}, nil
}

type TransientService struct {
	ID string
}

func createTransientService(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	return &TransientService{ID: time.Now().String()}, nil
}

type DependentService struct {
	Dependency *TestService
}

func createDependentService(ctx context.Context, container *EnhancedContainer) (interface{}, error) {
	// This will fail if "testService" is not registered
	dep, err := GetTyped[*TestService](container, "testService")
	if err != nil {
		return nil, err
	}
	return &DependentService{Dependency: dep}, nil
}

// TestLifecycleService implements ServiceLifecycle for testing
type TestLifecycleService struct {
	started bool
}

func (t *TestLifecycleService) Start(ctx context.Context) error {
	t.started = true
	return nil
}

func (t *TestLifecycleService) Stop(ctx context.Context) error {
	t.started = false
	return nil
}

func (t *TestLifecycleService) Health(ctx context.Context) error {
	if !t.started {
		return assert.AnError
	}
	return nil
}

// TestMigrationPatterns demonstrates migration from old to new container
func TestMigrationPatterns(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// OLD PATTERN (using legacy DI container)
	oldContainer := NewDIContainer(logger)

	// Simulate legacy registration
	// oldContainer.RegisterSomething(...)

	// NEW PATTERN (using enhanced container)
	newContainer := NewContainerBuilder(ctx, logger).
		WithSingleton("modernService", createTestService).
		WithSingleton("anotherService", createAnotherTestService).
		MustBuild()

	err := newContainer.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := newContainer.Stop(ctx); err != nil {
			t.Errorf("Failed to stop container: %v", err)
		}
	}()

	// Test that new container works
	service, err := GetTyped[*TestService](newContainer, "modernService")
	assert.NoError(t, err)
	assert.NotNil(t, service)

	// Demonstrate that both can coexist during migration
	assert.NotNil(t, oldContainer)
	assert.NotNil(t, newContainer)
}

// BenchmarkContainerPerformance benchmarks container operations
func BenchmarkContainerPerformance(b *testing.B) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	container := NewContainerBuilder(ctx, logger).
		WithSingleton("service1", createTestService).
		WithSingleton("service2", createAnotherTestService).
		MustBuild()

	if err := container.Start(ctx); err != nil {
		b.Fatalf("Failed to start container: %v", err)
	}
	defer func() {
		if err := container.Stop(ctx); err != nil {
			b.Errorf("Failed to stop container: %v", err)
		}
	}()

	b.ResetTimer()

	// Benchmark service retrieval
	b.Run("GetService", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := container.Get("service1")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Benchmark typed service retrieval
	b.Run("GetTypedService", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := GetTyped[*TestService](container, "service1")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Benchmark health checks
	b.Run("HealthCheck", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := container.Health(ctx)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
