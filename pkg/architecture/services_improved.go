// Package architecture - Enhanced Domain Services with Lifecycle Management
package architecture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Enhanced service implementations with proper lifecycle management

// EnhancedInfrastructureService provides infrastructure management with lifecycle support
type EnhancedInfrastructureService struct {
	provider        InfrastructureProvider
	containerMgr    ContainerManager
	serviceMgr      ServiceManager
	auditRepo       AuditRepository
	logger          *zap.Logger
	
	// Lifecycle management
	ctx             context.Context
	cancel          context.CancelFunc
	started         bool
	mu              sync.RWMutex
	healthCheck     *time.Ticker
	metrics         *ServiceMetrics
}

// ServiceMetrics tracks service performance and health
type ServiceMetrics struct {
	RequestCount    int64         `json:"request_count"`
	ErrorCount      int64         `json:"error_count"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastHealthCheck time.Time     `json:"last_health_check"`
	StartTime       time.Time     `json:"start_time"`
	mu              sync.RWMutex
}

// NewEnhancedInfrastructureService creates an enhanced infrastructure service
func NewEnhancedInfrastructureService(
	provider InfrastructureProvider,
	containerMgr ContainerManager,
	serviceMgr ServiceManager,
	auditRepo AuditRepository,
	logger *zap.Logger,
) *EnhancedInfrastructureService {
	return &EnhancedInfrastructureService{
		provider:     provider,
		containerMgr: containerMgr,
		serviceMgr:   serviceMgr,
		auditRepo:    auditRepo,
		logger:       logger,
		metrics: &ServiceMetrics{
			StartTime: time.Now(),
		},
	}
}

// Start implements ServiceLifecycle
func (s *EnhancedInfrastructureService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("service already started")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	
	// Start health check routine
	s.healthCheck = time.NewTicker(30 * time.Second)
	go s.healthCheckRoutine()

	s.started = true
	s.logger.Info("Infrastructure service started")
	
	return nil
}

// Stop implements ServiceLifecycle
func (s *EnhancedInfrastructureService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	if s.healthCheck != nil {
		s.healthCheck.Stop()
	}

	if s.cancel != nil {
		s.cancel()
	}

	s.started = false
	s.logger.Info("Infrastructure service stopped")
	
	return nil
}

// Health implements ServiceLifecycle
func (s *EnhancedInfrastructureService) Health(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.started {
		return fmt.Errorf("service not started")
	}

	// Perform basic health checks
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Check provider health
	if _, err := s.provider.GetNetworkInfo(healthCtx); err != nil {
		return fmt.Errorf("provider health check failed: %w", err)
	}

	// Check container manager health
	if _, err := s.containerMgr.ListContainers(healthCtx); err != nil {
		return fmt.Errorf("container manager health check failed: %w", err)
	}

	s.metrics.mu.Lock()
	s.metrics.LastHealthCheck = time.Now()
	s.metrics.mu.Unlock()

	return nil
}

// GetInfrastructureStatus retrieves comprehensive infrastructure status with enhanced monitoring
func (s *EnhancedInfrastructureService) GetInfrastructureStatus(ctx context.Context, userID string) (*EnhancedInfrastructureStatus, error) {
	start := time.Now()
	defer s.updateMetrics(start, nil)

	if !s.isStarted() {
		return nil, fmt.Errorf("service not started")
	}

	// Create enhanced status with timeout
	statusCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status := &EnhancedInfrastructureStatus{
		Timestamp: time.Now(),
		RequestID: generateRequestID(),
	}

	// Parallel collection of status information
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	// Get servers
	wg.Add(1)
	go func() {
		defer wg.Done()
		if servers, err := s.provider.GetServers(statusCtx); err != nil {
			mu.Lock()
			errors = append(errors, fmt.Errorf("servers: %w", err))
			mu.Unlock()
		} else {
			mu.Lock()
			status.Servers = servers
			mu.Unlock()
		}
	}()

	// Get containers
	wg.Add(1)
	go func() {
		defer wg.Done()
		if containers, err := s.containerMgr.ListContainers(statusCtx); err != nil {
			mu.Lock()
			errors = append(errors, fmt.Errorf("containers: %w", err))
			mu.Unlock()
		} else {
			mu.Lock()
			status.Containers = containers
			mu.Unlock()
		}
	}()

	// Get services
	wg.Add(1)
	go func() {
		defer wg.Done()
		if services, err := s.serviceMgr.ListServices(statusCtx); err != nil {
			mu.Lock()
			errors = append(errors, fmt.Errorf("services: %w", err))
			mu.Unlock()
		} else {
			mu.Lock()
			status.Services = services
			mu.Unlock()
		}
	}()

	// Get network info
	wg.Add(1)
	go func() {
		defer wg.Done()
		if network, err := s.provider.GetNetworkInfo(statusCtx); err != nil {
			mu.Lock()
			errors = append(errors, fmt.Errorf("network: %w", err))
			mu.Unlock()
		} else {
			mu.Lock()
			status.Network = network
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Add service metrics
	status.Metrics = s.getMetricsSnapshot()

	// Log errors but don't fail completely
	if len(errors) > 0 {
		for _, err := range errors {
			s.logger.Warn("Partial status collection failure", zap.Error(err))
		}
		status.PartialErrors = errors
	}

	// Audit log
	go s.auditStatusRequest(ctx, userID, start, status, errors)

	s.logger.Info("Infrastructure status retrieved",
		zap.String("request_id", status.RequestID),
		zap.Int("servers", len(status.Servers)),
		zap.Int("containers", len(status.Containers)),
		zap.Int("services", len(status.Services)),
		zap.Int("errors", len(errors)),
		zap.Duration("duration", time.Since(start)),
	)

	return status, nil
}

// CreateServerWithTimeout creates a server with enhanced timeout and retry logic
func (s *EnhancedInfrastructureService) CreateServerWithTimeout(ctx context.Context, userID string, spec *ServerSpec, timeout time.Duration) (*Server, error) {
	start := time.Now()
	
	if !s.isStarted() {
		return nil, fmt.Errorf("service not started")
	}

	// Create context with timeout
	createCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Enhanced validation
	if err := s.validateServerSpecEnhanced(spec); err != nil {
		s.updateMetrics(start, err)
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Attempt creation with retry logic
	var server *Server
	var err error
	
	for attempt := 1; attempt <= 3; attempt++ {
		server, err = s.provider.CreateServer(createCtx, spec)
		if err == nil {
			break
		}
		
		if attempt < 3 {
			s.logger.Warn("Server creation attempt failed, retrying",
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
			
			select {
			case <-createCtx.Done():
				s.updateMetrics(start, createCtx.Err())
				return nil, fmt.Errorf("server creation timeout: %w", createCtx.Err())
			case <-time.After(time.Duration(attempt) * time.Second):
				// Continue to next attempt
			}
		}
	}

	if err != nil {
		s.updateMetrics(start, err)
		go s.auditServerCreation(ctx, userID, spec, nil, err, start)
		return nil, fmt.Errorf("server creation failed after 3 attempts: %w", err)
	}

	// Success
	s.updateMetrics(start, nil)
	go s.auditServerCreation(ctx, userID, spec, server, nil, start)

	s.logger.Info("Server created successfully",
		zap.String("server_id", server.ID),
		zap.String("server_name", server.Name),
		zap.Duration("duration", time.Since(start)),
	)

	return server, nil
}

// GetMetrics returns current service metrics
func (s *EnhancedInfrastructureService) GetMetrics() *ServiceMetrics {
	return s.getMetricsSnapshot()
}

// healthCheckRoutine runs periodic health checks
func (s *EnhancedInfrastructureService) healthCheckRoutine() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.healthCheck.C:
			if err := s.Health(s.ctx); err != nil {
				s.logger.Warn("Health check failed", zap.Error(err))
			}
		}
	}
}

// Helper methods

func (s *EnhancedInfrastructureService) isStarted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

func (s *EnhancedInfrastructureService) updateMetrics(start time.Time, err error) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	
	s.metrics.RequestCount++
	if err != nil {
		s.metrics.ErrorCount++
	}
	
	// Update average latency (simple moving average)
	latency := time.Since(start)
	if s.metrics.RequestCount == 1 {
		s.metrics.AverageLatency = latency
	} else {
		s.metrics.AverageLatency = (s.metrics.AverageLatency + latency) / 2
	}
}

func (s *EnhancedInfrastructureService) getMetricsSnapshot() *ServiceMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	
	return &ServiceMetrics{
		RequestCount:    s.metrics.RequestCount,
		ErrorCount:      s.metrics.ErrorCount,
		AverageLatency:  s.metrics.AverageLatency,
		LastHealthCheck: s.metrics.LastHealthCheck,
		StartTime:       s.metrics.StartTime,
	}
}

func (s *EnhancedInfrastructureService) validateServerSpecEnhanced(spec *ServerSpec) error {
	if spec == nil {
		return fmt.Errorf("server spec cannot be nil")
	}

	if spec.Name == "" {
		return fmt.Errorf("server name is required")
	}

	if len(spec.Name) > 63 {
		return fmt.Errorf("server name too long (max 63 characters)")
	}

	if spec.Type == "" {
		return fmt.Errorf("server type is required")
	}

	if spec.Image == "" {
		return fmt.Errorf("server image is required")
	}

	// Validate labels
	for key, value := range spec.Labels {
		if len(key) > 63 || len(value) > 255 {
			return fmt.Errorf("label '%s' exceeds size limits", key)
		}
	}

	return nil
}

func (s *EnhancedInfrastructureService) auditStatusRequest(ctx context.Context, userID string, start time.Time, status *EnhancedInfrastructureStatus, errors []error) {
	result := "success"
	details := map[string]string{
		"request_id": status.RequestID,
		"duration":   time.Since(start).String(),
		"servers":    fmt.Sprintf("%d", len(status.Servers)),
		"containers": fmt.Sprintf("%d", len(status.Containers)),
		"services":   fmt.Sprintf("%d", len(status.Services)),
	}

	if len(errors) > 0 {
		result = "partial_success"
		details["errors"] = fmt.Sprintf("%d", len(errors))
	}

	_ = s.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "infrastructure.status.get",
		Resource:  "infrastructure",
		Details:   details,
		Result:    result,
	})
}

func (s *EnhancedInfrastructureService) auditServerCreation(ctx context.Context, userID string, spec *ServerSpec, server *Server, err error, start time.Time) {
	result := "success"
	resource := fmt.Sprintf("server:%s", spec.Name)
	details := map[string]string{
		"server_name": spec.Name,
		"server_type": spec.Type,
		"duration":    time.Since(start).String(),
	}

	if err != nil {
		result = "failure"
		details["error"] = err.Error()
	} else if server != nil {
		resource = fmt.Sprintf("server:%s", server.ID)
		details["server_id"] = server.ID
		details["provider"] = server.Provider
	}

	_ = s.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "server.create",
		Resource:  resource,
		Details:   details,
		Result:    result,
	})
}

// EnhancedInfrastructureStatus extends the basic status with additional monitoring data
type EnhancedInfrastructureStatus struct {
	RequestID     string           `json:"request_id"`
	Timestamp     time.Time        `json:"timestamp"`
	Servers       []*Server        `json:"servers,omitempty"`
	Containers    []*Container     `json:"containers,omitempty"`
	Services      []*Service       `json:"services,omitempty"`
	Network       *NetworkInfo     `json:"network,omitempty"`
	Metrics       *ServiceMetrics  `json:"metrics,omitempty"`
	PartialErrors []error          `json:"-"` // Errors that occurred during collection
}

// generateRequestID creates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}