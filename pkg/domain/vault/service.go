// Package vault implements domain services for secret management
package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Service contains the business logic for vault operations
type Service struct {
	secretStore   SecretStore
	authenticator VaultAuthenticator
	manager       VaultManager
	configRepo    ConfigRepository
	auditRepo     AuditRepository
	logger        *zap.Logger
}

// NewService creates a new vault domain service
func NewService(
	secretStore SecretStore,
	authenticator VaultAuthenticator,
	manager VaultManager,
	configRepo ConfigRepository,
	auditRepo AuditRepository,
	logger *zap.Logger,
) *Service {
	return &Service{
		secretStore:   secretStore,
		authenticator: authenticator,
		manager:       manager,
		configRepo:    configRepo,
		auditRepo:     auditRepo,
		logger:        logger,
	}
}

// GetSecret retrieves a secret with audit logging
func (s *Service) GetSecret(ctx context.Context, userID, key string) (*Secret, error) {
	start := time.Now()

	// Always create audit event, even for validation failures
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "secret_get",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "read",
			Path:      key,
		},
	}

	// Validate input
	if userID == "" {
		auditEvent.Error = "user ID is required"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return nil, fmt.Errorf("user ID is required")
	}
	if key == "" {
		auditEvent.Error = "secret key is required"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return nil, fmt.Errorf("secret key is required")
	}

	// Get secret from store
	secret, err := s.secretStore.Get(ctx, key)

	// Update audit event with final duration
	auditEvent.Auth.Metadata["duration"] = time.Since(start).String()

	if err != nil {
		auditEvent.Error = err.Error()
		s.logger.Error("Failed to get secret",
			zap.String("user", userID),
			zap.String("key", key),
			zap.Error(err))
	} else {
		s.logger.Info("Secret retrieved successfully",
			zap.String("user", userID),
			zap.String("key", key))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return secret, err
}

// SetSecret stores a secret with validation and audit logging
func (s *Service) SetSecret(ctx context.Context, userID string, secret *Secret) error {
	start := time.Now()

	// Create audit event early
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "secret_set",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "write",
		},
	}

	// Validate input
	if userID == "" {
		auditEvent.Error = "user ID is required"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return fmt.Errorf("user ID is required")
	}
	if secret == nil {
		auditEvent.Error = "secret cannot be nil"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return fmt.Errorf("secret cannot be nil")
	}
	if err := s.validateSecret(secret); err != nil {
		auditEvent.Error = fmt.Sprintf("invalid secret: %v", err)
		auditEvent.Request.Path = "unknown" // Can't get path from nil secret
		_ = s.auditRepo.Record(ctx, auditEvent)
		return fmt.Errorf("invalid secret: %w", err)
	}

	// Now we know secret is valid, set the path
	auditEvent.Request.Path = secret.Key

	// Set timestamps
	now := time.Now()
	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = now
	}
	secret.UpdatedAt = now

	// Store secret
	err := s.secretStore.Set(ctx, secret.Key, secret)

	// Update audit event
	auditEvent.Auth.Metadata["duration"] = time.Since(start).String()
	auditEvent.Request.Data = map[string]interface{}{
		"key_length":   len(secret.Key),
		"has_metadata": len(secret.Metadata) > 0,
		"has_expiry":   secret.ExpiresAt != nil,
	}

	if err != nil {
		auditEvent.Error = err.Error()
		s.logger.Error("Failed to set secret",
			zap.String("user", userID),
			zap.String("key", secret.Key),
			zap.Error(err))
	} else {
		s.logger.Info("Secret stored successfully",
			zap.String("user", userID),
			zap.String("key", secret.Key))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return err
}

// DeleteSecret removes a secret with audit logging
func (s *Service) DeleteSecret(ctx context.Context, userID, key string) error {
	start := time.Now()

	// Create audit event early
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "secret_delete",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "delete",
			Path:      key,
		},
	}

	// Validate input
	if userID == "" {
		auditEvent.Error = "user ID is required"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return fmt.Errorf("user ID is required")
	}
	if key == "" {
		auditEvent.Error = "secret key is required"
		_ = s.auditRepo.Record(ctx, auditEvent)
		return fmt.Errorf("secret key is required")
	}

	// Delete secret
	err := s.secretStore.Delete(ctx, key)

	// Update audit event with final duration
	auditEvent.Auth.Metadata["duration"] = time.Since(start).String()

	if err != nil {
		auditEvent.Error = err.Error()
		s.logger.Error("Failed to delete secret",
			zap.String("user", userID),
			zap.String("key", key),
			zap.Error(err))
	} else {
		s.logger.Info("Secret deleted successfully",
			zap.String("user", userID),
			zap.String("key", key))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return err
}

// ListSecrets returns secrets under a prefix with audit logging
func (s *Service) ListSecrets(ctx context.Context, userID, prefix string) ([]*Secret, error) {
	start := time.Now()

	// Validate input
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	// List secrets
	secrets, err := s.secretStore.List(ctx, prefix)

	// Audit the operation
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "secret_list",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "list",
			Path:      prefix,
		},
	}

	if err != nil {
		auditEvent.Error = err.Error()
		s.logger.Error("Failed to list secrets",
			zap.String("user", userID),
			zap.String("prefix", prefix),
			zap.Error(err))
	} else {
		auditEvent.Response = &AuditResponse{
			Data: map[string]interface{}{
				"count": len(secrets),
			},
		}
		s.logger.Info("Secrets listed successfully",
			zap.String("user", userID),
			zap.String("prefix", prefix),
			zap.Int("count", len(secrets)))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return secrets, err
}

// AuthenticateUser performs user authentication with audit logging
func (s *Service) AuthenticateUser(ctx context.Context, method string, credentials map[string]string) (*AuthResult, error) {
	start := time.Now()

	// Validate input
	if method == "" {
		return nil, fmt.Errorf("authentication method is required")
	}
	if len(credentials) == 0 {
		return nil, fmt.Errorf("credentials are required")
	}

	// Perform authentication
	result, err := s.authenticator.Authenticate(ctx, method, credentials)
	if result == nil {
		result = &AuthResult{
			Success:   false,
			Timestamp: time.Now(),
			Method:    method,
		}
	}

	// Set additional fields
	result.Timestamp = time.Now()
	result.Method = method
	if err != nil {
		result.ErrorMessage = err.Error()
	}

	// Audit the authentication attempt
	userID := extractUserIDFromCredentials(credentials)
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "auth",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"method":   method,
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "auth",
			Path:      fmt.Sprintf("auth/%s/login", method),
		},
	}

	if err != nil || !result.Success {
		auditEvent.Error = fmt.Sprintf("authentication failed: %v", err)
		s.logger.Warn("Authentication failed",
			zap.String("user", userID),
			zap.String("method", method),
			zap.Error(err))
	} else {
		auditEvent.Response = &AuditResponse{
			Data: map[string]interface{}{
				"token_ttl": result.TokenTTL.String(),
				"policies":  result.Policies,
				"renewable": result.Renewable,
			},
		}
		s.logger.Info("Authentication successful",
			zap.String("user", userID),
			zap.String("method", method),
			zap.Duration("token_ttl", result.TokenTTL))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return result, err
}

// GetAuthStatus returns current authentication status
func (s *Service) GetAuthStatus(ctx context.Context) (*AuthStatus, error) {
	return s.authenticator.GetAuthStatus(ctx)
}

// InitializeVault initializes vault with the provided configuration
func (s *Service) InitializeVault(ctx context.Context, userID string, config *InitConfig) (*InitResult, error) {
	start := time.Now()

	// Validate configuration
	if err := s.validateInitConfig(config); err != nil {
		return nil, fmt.Errorf("invalid init config: %w", err)
	}

	// Initialize vault
	result, err := s.manager.Initialize(ctx, config)

	// Audit the initialization
	auditEvent := &AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Type:      "vault_init",
		Auth: &AuditAuth{
			DisplayName: userID,
			Metadata: map[string]string{
				"duration": time.Since(start).String(),
			},
		},
		Request: &AuditRequest{
			ID:        generateRequestID(),
			Operation: "write",
			Path:      "sys/init",
			Data: map[string]interface{}{
				"secret_shares":    config.SecretShares,
				"secret_threshold": config.SecretThreshold,
			},
		},
	}

	if err != nil {
		auditEvent.Error = err.Error()
		s.logger.Error("Vault initialization failed",
			zap.String("user", userID),
			zap.Error(err))
	} else if result != nil {
		auditEvent.Response = &AuditResponse{
			Data: map[string]interface{}{
				"initialized": result.Initialized,
				"key_shares":  result.KeyShares,
				"threshold":   result.KeyThreshold,
			},
		}
		s.logger.Info("Vault initialization successful",
			zap.String("user", userID),
			zap.Int("key_shares", result.KeyShares),
			zap.Int("threshold", result.KeyThreshold))
	}

	// Record audit event
	_ = s.auditRepo.Record(ctx, auditEvent)

	return result, err
}

// GetVaultStatus returns vault health and status
func (s *Service) GetVaultStatus(ctx context.Context) (*VaultStatus, error) {
	return s.manager.GetStatus(ctx)
}

// validateSecret validates secret data
func (s *Service) validateSecret(secret *Secret) error {
	if secret == nil {
		return fmt.Errorf("secret cannot be nil")
	}
	if secret.Key == "" {
		return fmt.Errorf("secret key is required")
	}
	if secret.Value == "" {
		return fmt.Errorf("secret value is required")
	}
	if strings.Contains(secret.Key, "..") {
		return fmt.Errorf("secret key cannot contain '..'")
	}
	if len(secret.Key) > 1024 {
		return fmt.Errorf("secret key too long (max 1024 characters)")
	}
	if len(secret.Value) > 1024*1024 {
		return fmt.Errorf("secret value too long (max 1MB)")
	}
	return nil
}

// validateInitConfig validates vault initialization configuration
func (s *Service) validateInitConfig(config *InitConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if config.SecretShares < 1 || config.SecretShares > 255 {
		return fmt.Errorf("secret_shares must be between 1 and 255")
	}
	if config.SecretThreshold < 1 || config.SecretThreshold > config.SecretShares {
		return fmt.Errorf("secret_threshold must be between 1 and secret_shares")
	}
	return nil
}

// extractUserIDFromCredentials extracts user ID from credentials map
func extractUserIDFromCredentials(credentials map[string]string) string {
	if username, ok := credentials["username"]; ok {
		return username
	}
	if roleID, ok := credentials["role_id"]; ok {
		return roleID
	}
	return "unknown"
}

// generateAuditID generates a unique audit event ID
func generateAuditID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
