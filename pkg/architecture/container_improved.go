// Package architecture - Enhanced Dependency Injection Container
package architecture

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ServiceLifecycle defines service lifecycle management
type ServiceLifecycle interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) error
}

// ServiceRegistration holds service registration information
type ServiceRegistration struct {
	Name      string
	Type      reflect.Type
	Instance  interface{}
	Lifecycle ServiceLifecycle
	Singleton bool
	Factory   func(ctx context.Context, container *EnhancedContainer) (interface{}, error)
}

// EnhancedContainer provides advanced dependency injection with lifecycle management
type EnhancedContainer struct {
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *zap.Logger
	registrations map[string]*ServiceRegistration
	instances     map[string]interface{}
	started       bool
	startTime     time.Time
}

// NewEnhancedContainer creates a new enhanced dependency injection container
func NewEnhancedContainer(ctx context.Context, logger *zap.Logger) *EnhancedContainer {
	containerCtx, cancel := context.WithCancel(ctx)
	
	return &EnhancedContainer{
		ctx:           containerCtx,
		cancel:        cancel,
		logger:        logger,
		registrations: make(map[string]*ServiceRegistration),
		instances:     make(map[string]interface{}),
		started:       false,
	}
}

// RegisterSingleton registers a singleton service with optional lifecycle
func (c *EnhancedContainer) RegisterSingleton(name string, factory func(ctx context.Context, container *EnhancedContainer) (interface{}, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.registrations[name] = &ServiceRegistration{
		Name:      name,
		Singleton: true,
		Factory:   factory,
	}
	
	c.logger.Debug("Singleton service registered", zap.String("name", name))
}

// RegisterTransient registers a transient service (new instance each time)
func (c *EnhancedContainer) RegisterTransient(name string, factory func(ctx context.Context, container *EnhancedContainer) (interface{}, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.registrations[name] = &ServiceRegistration{
		Name:      name,
		Singleton: false,
		Factory:   factory,
	}
	
	c.logger.Debug("Transient service registered", zap.String("name", name))
}

// RegisterInstance registers a pre-created instance
func (c *EnhancedContainer) RegisterInstance(name string, instance interface{}) error {
	if instance == nil {
		return fmt.Errorf("cannot register nil instance for service '%s'", name)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if instance implements lifecycle
	var lifecycle ServiceLifecycle
	if lc, ok := instance.(ServiceLifecycle); ok {
		lifecycle = lc
	}

	c.registrations[name] = &ServiceRegistration{
		Name:      name,
		Type:      reflect.TypeOf(instance),
		Instance:  instance,
		Lifecycle: lifecycle,
		Singleton: true,
	}
	
	c.instances[name] = instance
	
	c.logger.Debug("Instance registered", 
		zap.String("name", name),
		zap.String("type", reflect.TypeOf(instance).String()),
	)
	
	return nil
}

// Get retrieves a service by name with proper error handling
func (c *EnhancedContainer) Get(name string) (interface{}, error) {
	c.mu.RLock()
	registration, exists := c.registrations[name]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("service '%s' not registered", name)
	}

	// Return existing instance if singleton
	if registration.Singleton {
		c.mu.RLock()
		if instance, exists := c.instances[name]; exists {
			c.mu.RUnlock()
			return instance, nil
		}
		c.mu.RUnlock()
	}

	// Create new instance
	return c.createInstance(name, registration)
}

// GetTyped retrieves a service with type safety
func GetTyped[T any](c *EnhancedContainer, name string) (T, error) {
	var zero T
	
	instance, err := c.Get(name)
	if err != nil {
		return zero, err
	}
	
	typed, ok := instance.(T)
	if !ok {
		return zero, fmt.Errorf("service '%s' is not of expected type %T", name, zero)
	}
	
	return typed, nil
}

// MustGet retrieves a service or panics if not found
func (c *EnhancedContainer) MustGet(name string) interface{} {
	instance, err := c.Get(name)
	if err != nil {
		panic(fmt.Sprintf("failed to get service '%s': %v", name, err))
	}
	return instance
}

// Start initializes all registered services with lifecycle support
func (c *EnhancedContainer) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("container already started")
	}

	c.startTime = time.Now()
	
	c.logger.Info("Starting container", zap.Int("services", len(c.registrations)))

	// Start all services with lifecycle support
	for name, registration := range c.registrations {
		if registration.Lifecycle != nil {
			if err := registration.Lifecycle.Start(ctx); err != nil {
				c.logger.Error("Failed to start service", 
					zap.String("service", name),
					zap.Error(err),
				)
				return fmt.Errorf("failed to start service '%s': %w", name, err)
			}
			c.logger.Debug("Service started", zap.String("service", name))
		}
	}

	c.started = true
	
	c.logger.Info("Container started successfully", 
		zap.Duration("startup_time", time.Since(c.startTime)),
	)
	
	return nil
}

// Stop gracefully shuts down all services
func (c *EnhancedContainer) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return nil
	}

	c.logger.Info("Stopping container")
	
	// Stop services in reverse order
	var services []string
	for name := range c.registrations {
		services = append(services, name)
	}
	
	// Reverse slice
	for i := len(services)/2 - 1; i >= 0; i-- {
		opp := len(services) - 1 - i
		services[i], services[opp] = services[opp], services[i]
	}

	for _, name := range services {
		registration := c.registrations[name]
		if registration.Lifecycle != nil {
			if err := registration.Lifecycle.Stop(ctx); err != nil {
				c.logger.Error("Failed to stop service", 
					zap.String("service", name),
					zap.Error(err),
				)
				// Continue stopping other services
			} else {
				c.logger.Debug("Service stopped", zap.String("service", name))
			}
		}
	}

	c.cancel()
	c.started = false
	
	c.logger.Info("Container stopped successfully")
	return nil
}

// Health checks the health of all services
func (c *EnhancedContainer) Health(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.started {
		return fmt.Errorf("container not started")
	}

	var unhealthyServices []string
	
	for name, registration := range c.registrations {
		if registration.Lifecycle != nil {
			if err := registration.Lifecycle.Health(ctx); err != nil {
				unhealthyServices = append(unhealthyServices, name)
				c.logger.Warn("Service health check failed", 
					zap.String("service", name),
					zap.Error(err),
				)
			}
		}
	}

	if len(unhealthyServices) > 0 {
		return fmt.Errorf("unhealthy services: %v", unhealthyServices)
	}

	return nil
}

// GetServiceNames returns all registered service names
func (c *EnhancedContainer) GetServiceNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, 0, len(c.registrations))
	for name := range c.registrations {
		names = append(names, name)
	}
	return names
}

// GetServiceInfo returns detailed information about a service
func (c *EnhancedContainer) GetServiceInfo(name string) (*ServiceInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	registration, exists := c.registrations[name]
	if !exists {
		return nil, fmt.Errorf("service '%s' not registered", name)
	}

	info := &ServiceInfo{
		Name:      registration.Name,
		Singleton: registration.Singleton,
		HasLifecycle: registration.Lifecycle != nil,
	}

	if registration.Type != nil {
		info.Type = registration.Type.String()
	}

	if _, exists := c.instances[name]; exists {
		info.Instantiated = true
	}

	return info, nil
}

// Validate checks that all required dependencies are available
func (c *EnhancedContainer) Validate() error {
	// Get list of services to validate (without holding lock)
	c.mu.RLock()
	var serviceNames []string
	for name := range c.registrations {
		serviceNames = append(serviceNames, name)
	}
	serviceCount := len(c.registrations)
	c.mu.RUnlock()

	// Try to resolve all dependencies (without holding lock)
	for _, name := range serviceNames {
		if _, err := c.Get(name); err != nil {
			return fmt.Errorf("validation failed for service '%s': %w", name, err)
		}
	}

	c.logger.Info("Container validation successful", 
		zap.Int("services", serviceCount),
	)

	return nil
}

// createInstance creates a new service instance
func (c *EnhancedContainer) createInstance(name string, registration *ServiceRegistration) (interface{}, error) {
	// Use pre-created instance
	if registration.Instance != nil {
		return registration.Instance, nil
	}

	// Use factory
	if registration.Factory != nil {
		start := time.Now()
		
		instance, err := registration.Factory(c.ctx, c)
		if err != nil {
			c.logger.Error("Factory failed to create service", 
				zap.String("service", name),
				zap.Error(err),
			)
			return nil, fmt.Errorf("factory failed for service '%s': %w", name, err)
		}

		// Store singleton instances
		if registration.Singleton {
			c.mu.Lock()
			c.instances[name] = instance
			c.mu.Unlock()
		}

		c.logger.Debug("Service instance created", 
			zap.String("service", name),
			zap.Duration("creation_time", time.Since(start)),
		)

		return instance, nil
	}

	return nil, fmt.Errorf("no factory or instance available for service '%s'", name)
}

// ServiceInfo provides information about a registered service
type ServiceInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Singleton    bool   `json:"singleton"`
	HasLifecycle bool   `json:"has_lifecycle"`
	Instantiated bool   `json:"instantiated"`
}

// ContainerBuilder provides a fluent interface for container configuration
type ContainerBuilder struct {
	container *EnhancedContainer
	logger    *zap.Logger
}

// NewContainerBuilder creates a new container builder
func NewContainerBuilder(ctx context.Context, logger *zap.Logger) *ContainerBuilder {
	return &ContainerBuilder{
		container: NewEnhancedContainer(ctx, logger),
		logger:    logger,
	}
}

// WithSingleton adds a singleton service
func (b *ContainerBuilder) WithSingleton(name string, factory func(ctx context.Context, container *EnhancedContainer) (interface{}, error)) *ContainerBuilder {
	b.container.RegisterSingleton(name, factory)
	return b
}

// WithTransient adds a transient service
func (b *ContainerBuilder) WithTransient(name string, factory func(ctx context.Context, container *EnhancedContainer) (interface{}, error)) *ContainerBuilder {
	b.container.RegisterTransient(name, factory)
	return b
}

// WithInstance adds a pre-created instance
func (b *ContainerBuilder) WithInstance(name string, instance interface{}) *ContainerBuilder {
	if err := b.container.RegisterInstance(name, instance); err != nil {
		b.logger.Error("Failed to register instance", zap.String("name", name), zap.Error(err))
	}
	return b
}

// Build creates the final container with validation
func (b *ContainerBuilder) Build() (*EnhancedContainer, error) {
	if err := b.container.Validate(); err != nil {
		return nil, fmt.Errorf("container validation failed: %w", err)
	}
	return b.container, nil
}

// MustBuild creates the container or panics if validation fails
func (b *ContainerBuilder) MustBuild() *EnhancedContainer {
	container, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("container build failed: %v", err))
	}
	return container
}