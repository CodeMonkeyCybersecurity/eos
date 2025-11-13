package managers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ManagerRegistry provides centralized registration and access to resource managers
// This consolidates the scattered manager instances across the codebase
type ManagerRegistry struct {
	managers map[string]interface{}
	mu       sync.RWMutex
	config   *RegistryConfig
}

// RegistryConfig provides configuration for the manager registry
type RegistryConfig struct {
	EnableHealthChecks  bool          `json:"enable_health_checks"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	MaxConcurrentOps    int           `json:"max_concurrent_ops"`
	LogLevel            string        `json:"log_level"`
}

// DefaultRegistryConfig returns default configuration for the registry
func DefaultRegistryConfig() *RegistryConfig {
	return &RegistryConfig{
		EnableHealthChecks:  true,
		HealthCheckInterval: time.Minute * 5,
		MaxConcurrentOps:    10,
		LogLevel:            "info",
	}
}

var (
	globalRegistry *ManagerRegistry
	once           sync.Once
)

// GetGlobalRegistry returns the singleton manager registry
func GetGlobalRegistry() *ManagerRegistry {
	once.Do(func() {
		globalRegistry = NewManagerRegistry(DefaultRegistryConfig())
	})
	return globalRegistry
}

// NewManagerRegistry creates a new manager registry
func NewManagerRegistry(config *RegistryConfig) *ManagerRegistry {
	if config == nil {
		config = DefaultRegistryConfig()
	}

	return &ManagerRegistry{
		managers: make(map[string]interface{}),
		config:   config,
	}
}

// RegisterManager registers a resource manager with the given name
func (mr *ManagerRegistry) RegisterManager(name string, manager interface{}) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if _, exists := mr.managers[name]; exists {
		return fmt.Errorf("manager %s is already registered", name)
	}

	mr.managers[name] = manager
	return nil
}

// GetManager retrieves a registered manager by name and type
func (mr *ManagerRegistry) GetManager(name string) (interface{}, error) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	manager, exists := mr.managers[name]
	if !exists {
		return nil, fmt.Errorf("manager %s is not registered", name)
	}

	return manager, nil
}

// GetManagerTyped retrieves a registered manager by name with type assertion
func GetManagerTyped[T any](name string) (T, error) {
	var zero T
	registry := GetGlobalRegistry()

	manager, err := registry.GetManager(name)
	if err != nil {
		return zero, err
	}

	typed, ok := manager.(T)
	if !ok {
		return zero, fmt.Errorf("manager %s is not of expected type", name)
	}

	return typed, nil
}

// ListManagers returns a list of all registered manager names
func (mr *ManagerRegistry) ListManagers() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	names := make([]string, 0, len(mr.managers))
	for name := range mr.managers {
		names = append(names, name)
	}
	return names
}

// UnregisterManager removes a manager from the registry
func (mr *ManagerRegistry) UnregisterManager(name string) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if _, exists := mr.managers[name]; !exists {
		return fmt.Errorf("manager %s is not registered", name)
	}

	delete(mr.managers, name)
	return nil
}

// HealthCheckAll performs health checks on all registered managers that support it
func (mr *ManagerRegistry) HealthCheckAll(ctx context.Context) *RegistryHealthResult {
	logger := otelzap.Ctx(ctx)
	start := time.Now()

	result := &RegistryHealthResult{
		Overall:   HealthHealthy,
		Managers:  make(map[string]*HealthCheckResult),
		Timestamp: start,
		Errors:    make([]string, 0),
	}

	mr.mu.RLock()
	managers := make(map[string]interface{}, len(mr.managers))
	for name, manager := range mr.managers {
		managers[name] = manager
	}
	mr.mu.RUnlock()

	for name, manager := range managers {
		// Try to perform health check if the manager supports it
		if hcManager, ok := manager.(interface {
			HealthCheck(context.Context, string) (*HealthCheckResult, error)
		}); ok {
			hcResult, err := hcManager.HealthCheck(ctx, name)
			if err != nil {
				logger.Warn("Health check failed for manager",
					zap.String("manager", name),
					zap.Error(err))
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
				result.Overall = HealthDegraded
				continue
			}
			result.Managers[name] = hcResult

			// Update overall health based on individual results
			if hcResult.Overall == HealthCritical || hcResult.Overall == HealthUnhealthy {
				if result.Overall == HealthHealthy {
					result.Overall = HealthDegraded
				}
			}
		} else {
			// Manager doesn't support health checks
			result.Managers[name] = &HealthCheckResult{
				Overall:   HealthUnknown,
				Checks:    make(map[string]CheckResult),
				Duration:  0,
				Timestamp: time.Now(),
				Warnings:  []string{"Manager does not support health checks"},
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

// RegistryHealthResult represents the health status of all managers
type RegistryHealthResult struct {
	Overall   HealthState                   `json:"overall"`
	Managers  map[string]*HealthCheckResult `json:"managers"`
	Duration  time.Duration                 `json:"duration"`
	Timestamp time.Time                     `json:"timestamp"`
	Errors    []string                      `json:"errors,omitempty"`
}

// Start begins background health checking if enabled
func (mr *ManagerRegistry) Start(ctx context.Context) error {
	if !mr.config.EnableHealthChecks {
		return nil
	}

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting manager registry health checks",
		zap.Duration("interval", mr.config.HealthCheckInterval))

	go mr.healthCheckLoop(ctx)
	return nil
}

// healthCheckLoop runs periodic health checks on all managers
func (mr *ManagerRegistry) healthCheckLoop(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	ticker := time.NewTicker(mr.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping manager registry health check loop")
			return
		case <-ticker.C:
			result := mr.HealthCheckAll(ctx)
			if result.Overall != HealthHealthy {
				logger.Warn("Manager registry health check detected issues",
					zap.String("overall_health", string(result.Overall)),
					zap.Strings("errors", result.Errors))
			} else {
				logger.Debug("Manager registry health check completed successfully",
					zap.Duration("duration", result.Duration),
					zap.Int("managers_checked", len(result.Managers)))
			}
		}
	}
}

// Convenience functions for common manager types

// RegisterServiceManager registers a service manager
func RegisterServiceManager(name string, manager interface{}) error {
	return GetGlobalRegistry().RegisterManager("service."+name, manager)
}

// RegisterDatabaseManager registers a database manager
func RegisterDatabaseManager(name string, manager interface{}) error {
	return GetGlobalRegistry().RegisterManager("database."+name, manager)
}

// RegisterContainerManager registers a container manager
func RegisterContainerManager(name string, manager interface{}) error {
	return GetGlobalRegistry().RegisterManager("container."+name, manager)
}

// RegisterSecurityManager registers a security manager
func RegisterSecurityManager(name string, manager interface{}) error {
	return GetGlobalRegistry().RegisterManager("security."+name, manager)
}

// RegisterSystemManager registers a system configuration manager
func RegisterSystemManager(name string, manager interface{}) error {
	return GetGlobalRegistry().RegisterManager("system."+name, manager)
}
