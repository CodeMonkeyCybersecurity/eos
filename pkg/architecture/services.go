// Package architecture - Domain Services (Business Logic)
package architecture

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Domain Services - Contain business logic and orchestrate repository operations

// InfrastructureService orchestrates infrastructure operations
type InfrastructureService struct {
	provider        InfrastructureProvider
	containerMgr    ContainerManager
	serviceMgr      ServiceManager
	auditRepo       AuditRepository
	logger          *zap.Logger
}

// NewInfrastructureService creates a new infrastructure service
func NewInfrastructureService(
	provider InfrastructureProvider,
	containerMgr ContainerManager,
	serviceMgr ServiceManager,
	auditRepo AuditRepository,
	logger *zap.Logger,
) *InfrastructureService {
	return &InfrastructureService{
		provider:     provider,
		containerMgr: containerMgr,
		serviceMgr:   serviceMgr,
		auditRepo:    auditRepo,
		logger:       logger,
	}
}

// GetInfrastructureStatus retrieves comprehensive infrastructure status
func (s *InfrastructureService) GetInfrastructureStatus(ctx context.Context, userID string) (*InfrastructureStatus, error) {
	start := time.Now()

	// Record audit event
	defer func() {
		_ = s.auditRepo.Record(ctx, &AuditEvent{
			ID:        generateID(),
			Timestamp: time.Now(),
			User:      userID,
			Action:    "infrastructure.status.get",
			Resource:  "infrastructure",
			Details: map[string]string{
				"duration": time.Since(start).String(),
			},
			Result: "success",
		})
	}()

	status := &InfrastructureStatus{
		Timestamp: time.Now(),
	}

	// Get servers
	servers, err := s.provider.GetServers(ctx)
	if err != nil {
		s.logger.Error("Failed to get servers", zap.Error(err))
		// Don't fail completely - continue with other components
	} else {
		status.Servers = servers
	}

	// Get containers
	containers, err := s.containerMgr.ListContainers(ctx)
	if err != nil {
		s.logger.Error("Failed to get containers", zap.Error(err))
	} else {
		status.Containers = containers
	}

	// Get services
	services, err := s.serviceMgr.ListServices(ctx)
	if err != nil {
		s.logger.Error("Failed to get services", zap.Error(err))
	} else {
		status.Services = services
	}

	// Get network info
	network, err := s.provider.GetNetworkInfo(ctx)
	if err != nil {
		s.logger.Error("Failed to get network info", zap.Error(err))
	} else {
		status.Network = network
	}

	s.logger.Info("Infrastructure status retrieved",
		zap.Int("servers", len(status.Servers)),
		zap.Int("containers", len(status.Containers)),
		zap.Int("services", len(status.Services)),
		zap.Duration("duration", time.Since(start)),
	)

	return status, nil
}

// CreateServer creates a new server with validation and audit logging
func (s *InfrastructureService) CreateServer(ctx context.Context, userID string, spec *ServerSpec) (*Server, error) {
	start := time.Now()

	// Validate spec
	if err := s.validateServerSpec(spec); err != nil {
		return nil, fmt.Errorf("invalid server spec: %w", err)
	}

	// Create server
	server, err := s.provider.CreateServer(ctx, spec)
	if err != nil {
		_ = s.auditRepo.Record(ctx, &AuditEvent{
			ID:        generateID(),
			Timestamp: time.Now(),
			User:      userID,
			Action:    "server.create",
			Resource:  fmt.Sprintf("server:%s", spec.Name),
			Details: map[string]string{
				"error":    err.Error(),
				"duration": time.Since(start).String(),
			},
			Result: "failure",
		})
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	// Record successful creation
	_ = s.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "server.create",
		Resource:  fmt.Sprintf("server:%s", server.ID),
		Details: map[string]string{
			"server_name": server.Name,
			"provider":    server.Provider,
			"duration":    time.Since(start).String(),
		},
		Result: "success",
	})

	s.logger.Info("Server created successfully",
		zap.String("server_id", server.ID),
		zap.String("server_name", server.Name),
		zap.Duration("duration", time.Since(start)),
	)

	return server, nil
}

// validateServerSpec validates server creation parameters
func (s *InfrastructureService) validateServerSpec(spec *ServerSpec) error {
	if spec == nil {
		return fmt.Errorf("server spec cannot be nil")
	}

	if spec.Name == "" {
		return fmt.Errorf("server name is required")
	}

	if spec.Type == "" {
		return fmt.Errorf("server type is required")
	}

	if spec.Image == "" {
		return fmt.Errorf("server image is required")
	}

	// Additional validation logic here
	return nil
}

// SecretService manages secrets with proper access control
type SecretService struct {
	store     SecretStore
	auditRepo AuditRepository
	logger    *zap.Logger
}

// NewSecretService creates a new secret service
func NewSecretService(store SecretStore, auditRepo AuditRepository, logger *zap.Logger) *SecretService {
	return &SecretService{
		store:     store,
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// GetSecret retrieves a secret with audit logging
func (s *SecretService) GetSecret(ctx context.Context, userID, key string) (*Secret, error) {
	start := time.Now()

	secret, err := s.store.Get(ctx, key)

	// Always audit secret access attempts (success or failure)
	result := "success"
	details := map[string]string{
		"duration": time.Since(start).String(),
	}

	if err != nil {
		result = "failure"
		details["error"] = err.Error()
	}

	_ = s.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "secret.get",
		Resource:  fmt.Sprintf("secret:%s", key),
		Details:   details,
		Result:    result,
	})

	if err != nil {
		s.logger.Error("Failed to get secret", zap.String("key", key), zap.Error(err))
		return nil, err
	}

	s.logger.Info("Secret retrieved", zap.String("key", key))
	return secret, nil
}

// SetSecret stores a secret with validation and audit logging
func (s *SecretService) SetSecret(ctx context.Context, userID string, secret *Secret) error {
	start := time.Now()

	// Validate secret
	if err := s.validateSecret(secret); err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}

	err := s.store.Set(ctx, secret.Key, secret)

	// Audit the operation
	result := "success"
	details := map[string]string{
		"duration": time.Since(start).String(),
	}

	if err != nil {
		result = "failure"
		details["error"] = err.Error()
	}

	_ = s.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "secret.set",
		Resource:  fmt.Sprintf("secret:%s", secret.Key),
		Details:   details,
		Result:    result,
	})

	if err != nil {
		s.logger.Error("Failed to set secret", zap.String("key", secret.Key), zap.Error(err))
		return err
	}

	s.logger.Info("Secret stored", zap.String("key", secret.Key))
	return nil
}

// validateSecret validates secret data
func (s *SecretService) validateSecret(secret *Secret) error {
	if secret == nil {
		return fmt.Errorf("secret cannot be nil")
	}

	if secret.Key == "" {
		return fmt.Errorf("secret key is required")
	}

	if secret.Value == "" {
		return fmt.Errorf("secret value is required")
	}

	// Additional validation logic here
	return nil
}

// InfrastructureStatus represents comprehensive infrastructure status
type InfrastructureStatus struct {
	Timestamp  time.Time    `json:"timestamp"`
	Servers    []*Server    `json:"servers,omitempty"`
	Containers []*Container `json:"containers,omitempty"`
	Services   []*Service   `json:"services,omitempty"`
	Network    *NetworkInfo `json:"network,omitempty"`
}

// generateID generates a unique ID for audit events
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}